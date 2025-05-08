"""OAuth handling functionality for MCP server authentication.

Provides OAuth 2.0 authorization code flow implementation.
"""

import boto3
import httpx
import json
import jwt
import os
import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

# Import the token store factory
from token_storage import get_token_store
from urllib.parse import urlencode


# Initialize token store (either DynamoDB or local depending on environment)
token_store = get_token_store()


class OAuthMiddlewareCognito(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Skip auth for non-MCP endpoints, discovery endpoints, and OAuth endpoints
        if (
            request.url.path == '/'
            or request.url.path.startswith('/.well-known')
            or request.url.path == '/register'
            or request.url.path == '/authorize'
            or request.url.path == '/callback'
            or request.url.path == '/token'
        ):
            return await call_next(request)

        # Check for Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JSONResponse(
                {
                    'error': 'invalid_token',
                    'error_description': 'Missing or invalid authorization header',
                },
                status_code=401,
            )

        token = auth_header.replace('Bearer ', '')

        # Validate token
        is_valid, claims = await validate_token(token)
        if not is_valid:
            return JSONResponse(
                {
                    'error': 'invalid_token',
                    'error_description': 'Token validation failed',
                },
                status_code=401,
            )

        # Add claims to request state
        request.state.user = claims
        return await call_next(request)


# Function to retrieve SSM parameter and set environment variable
def get_ssm_parameter():
    """Get the HTTPS URL from SSM parameter store and set it in os.environ.

    Only fetches from SSM if MCP_SERVER_BASE_URL is not already set
    """
    # Skip if MCP_SERVER_BASE_URL is already set
    if os.environ.get('MCP_SERVER_BASE_URL'):
        print('MCP_SERVER_BASE_URL is already set, skipping SSM fetch')
        return

    try:
        param_name = os.environ.get('MCP_SERVER_BASE_URL_PARAMETER_NAME')
        if param_name:
            print(f'Retrieving SSM parameter: {param_name}')
            ssm_client = boto3.client('ssm')
            response = ssm_client.get_parameter(Name=param_name)
            https_url = response['Parameter']['Value']
            os.environ['MCP_SERVER_BASE_URL'] = https_url
            print(f'Set MCP_SERVER_BASE_URL to {https_url}')
        else:
            print('MCP_SERVER_BASE_URL_PARAMETER_NAME not set')
    except Exception as e:
        print(f'Error retrieving SSM parameter: {e}')
        # Don't fail if we can't get the parameter - we'll use the default


# OAuth 2.0 Authorization Server Metadata
async def oauth_metadata(request):
    """Return OAuth 2.0 Authorization Server Metadata according to RFC8414.
    
    This metadata points to the MCP server's own endpoints, not directly to Cognito.
    """
    base_url = str(request.base_url).rstrip('/')

    # Get Cognito domain from environment variables - for internal use only
    cognito_domain = os.environ.get('COGNITO_DOMAIN')
    region = os.environ.get('AWS_REGION', 'us-west-2')
    user_pool_id = os.environ.get('COGNITO_USER_POOL_ID')

    # For JWT key verification, we'll use Cognito's JWKS endpoint
    jwks_uri = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'

    # Return OAuth metadata pointing to the MCP server's endpoints
    return JSONResponse(
        {
            # REQUIRED fields
            'issuer': base_url,  # This is your MCP server
            'authorization_endpoint': f'{base_url}/authorize',  # Your authorize endpoint
            'token_endpoint': f'{base_url}/token',  # Your token endpoint
            # OPTIONAL but important fields
            'registration_endpoint': f'{base_url}/register',
            'jwks_uri': jwks_uri,  # Using Cognito's JWKS
            'response_types_supported': ['code'],
            'grant_types_supported': [
                'authorization_code',
                'refresh_token',
            ],
            'scopes_supported': [
                'openid',
                'email',
                'profile',
                'mcp-server/read',
                'mcp-server/write',
            ],
            'token_endpoint_auth_methods_supported': ['client_secret_basic', 'none'],
            'response_modes_supported': ['query', 'fragment'],
            'code_challenge_methods_supported': ['S256'],
            # Additional information
            'service_documentation': 'https://modelcontextprotocol.io/authorization',
            'revocation_endpoint': f'{base_url}/revoke',  # If implemented
            'introspection_endpoint': f'{base_url}/introspect',  # If implemented
        }
    )


# Dynamic client registration
async def register_client(request: Request):
    """Handle dynamic client registration requests following RFC 7591."""
    try:
        # Parse the request JSON body
        client_metadata = await request.json()

        # Validate required fields
        required_fields = ['redirect_uris', 'client_name']
        for field in required_fields:
            if field not in client_metadata:
                return JSONResponse(
                    {
                        'error': 'invalid_client_metadata',
                        'error_description': f'Missing required field: {field}',
                    },
                    status_code=400,
                )

        # Validate redirect URIs (must be HTTPS or localhost)
        for uri in client_metadata['redirect_uris']:
            if not (
                uri.startswith('https://')
                or uri.startswith('http://localhost')
                or uri.startswith('http://127.0.0.1')
            ):
                return JSONResponse(
                    {
                        'error': 'invalid_redirect_uri',
                        'error_description': 'Redirect URIs must use HTTPS or localhost',
                    },
                    status_code=400,
                )

        # Generate a client ID and secret
        client_id = str(uuid.uuid4())
        client_secret = str(uuid.uuid4())  # In production, use a more secure method

        # Store the client information with the generated client ID
        client_info = {
            'client_id': client_id,
            'client_secret': client_secret,
            'client_id_issued_at': int(time.time()),
            'client_secret_expires_at': 0,  # Never expires
            **client_metadata,  # Include all the provided metadata
        }

        # Save the client registration to DynamoDB using TokenStore
        await token_store.store_client(client_id, client_info)

        # Return the client information as required by the spec
        return JSONResponse(client_info)
    except Exception as e:
        return JSONResponse(
            {'error': 'invalid_client_metadata', 'error_description': str(e)},
            status_code=400,
        )


# Handle OAuth authorization requests
async def authorize(request: Request):
    """Handle OAuth authorization requests and redirect to Cognito for authentication.

    This implements the first step in the third-party OAuth flow.
    """
    # Ensure we have the latest base URL
    get_ssm_parameter()

    # 1. Extract and validate authorization request parameters
    client_id = request.query_params.get('client_id')
    redirect_uri = request.query_params.get('redirect_uri')
    response_type = request.query_params.get('response_type')
    state = request.query_params.get('state')
    code_challenge = request.query_params.get('code_challenge')
    code_challenge_method = request.query_params.get('code_challenge_method', 'S256')
    scope = request.query_params.get('scope', '')

    print("=== AUTHORIZE ENDPOINT ===")
    print(f"OAuth Request - client_id: {client_id}, redirect_uri: {redirect_uri}")

    # 2. Validate required parameters
    if not client_id or not redirect_uri or response_type != 'code':
        return JSONResponse(
            {
                'error': 'invalid_request',
                'error_description': 'Missing required parameters or invalid response_type',
            },
            status_code=400,
        )

    # 3. Validate the client and redirect URI
    client = await token_store.get_client(client_id)
    if not client:
        return JSONResponse(
            {
                'error': 'invalid_client',
                'error_description': 'Unknown client',
            },
            status_code=401,
        )

    if redirect_uri not in client['redirect_uris']:
        return JSONResponse(
            {
                'error': 'invalid_redirect_uri',
                'error_description': "Redirect URI doesn't match registered URIs",
            },
            status_code=400,
        )

    # 4. Generate a session ID to link this request with the upcoming third-party flow
    session_id = str(uuid.uuid4())

    print(f"Generated session_id: {session_id}")

    # 5. Store the original request parameters in a session store
    session_data = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
        'scope': scope,
        'created_at': time.time(),
    }

    print(f"Storing session data with client redirect_uri: {redirect_uri}")
    await token_store.store_session(session_id, session_data)

    # 6. Set up the request to the Cognito authorization server
    cognito_domain = os.environ.get('COGNITO_DOMAIN')
    region = os.environ.get('AWS_REGION', 'us-west-2')
    cognito_client_id = os.environ.get('COGNITO_CLIENT_ID')

    # Your server's callback endpoint that will receive the authorization code from Cognito (NOT THE CLIENT!)
    callback_url = f'{os.environ.get("MCP_SERVER_BASE_URL", f"http://localhost:{os.environ['PORT']}")}/callback'

    print(f"MCP Server callback URL for Cognito: {callback_url}")
    print(f"MCP Client redirect URI stored in session: {redirect_uri}")

    # Build the authorization URL for Cognito
    cognito_auth_url = (
        f'https://{cognito_domain}.auth.{region}.amazoncognito.com/oauth2/authorize'
        f'?client_id={cognito_client_id}'
        f'&response_type=code'
        f'&redirect_uri={callback_url}'
        f'&state={session_id}'  # Use the session ID as state for Cognito
    )

    # Add scopes if provided
    if scope:
        # Map MCP scopes to Cognito scopes as needed
        cognito_auth_url += f'&scope={scope}'

    # 7. Redirect the user to Cognito's authorization endpoint
    return RedirectResponse(cognito_auth_url, status_code=302)


# Handle callbacks from Cognito
async def callback(request: Request):
    """Handle callbacks from Cognito and redirect to the client with an MCP authorization code."""
    # 1. Extract parameters from the request
    code = request.query_params.get('code')
    state = request.query_params.get('state')  # This should be the session_id we sent
    error = request.query_params.get('error')

    print(f'Callback received: code={code}, state={state}, error={error}')

    # 2. Handle error cases
    if error:
        print(
            f'Error in callback: {error} - {request.query_params.get("error_description", "Unknown error")}'
        )
        return JSONResponse(
            {
                'error': error,
                'error_description': request.query_params.get(
                    'error_description', 'Unknown error'
                ),
            },
            status_code=400,
        )

    if not code or not state:
        print('Missing code or state parameter')
        return JSONResponse(
            {
                'error': 'invalid_request',
                'error_description': 'Missing code or state parameter',
            },
            status_code=400,
        )

    print("=== CALLBACK ENDPOINT ===")
    print(f"Callback received from Cognito: code={code}, state={state}")

    # 3. Retrieve the original session from DynamoDB
    session = await token_store.get_session(state)
    if not session:
        print(f'Invalid state: {state}. Session not found in DynamoDB.')
        return JSONResponse(
            {
                'error': 'invalid_state',
                'error_description': 'Invalid or expired state',
            },
            status_code=400,
        )

    print(f"Found session with client_id: {session['client_id']}")
    print(f"Client's original redirect_uri from session: {session['redirect_uri']}")

    # 4. Exchange the Cognito authorization code for tokens
    try:
        # Ensure we have the latest base URL
        get_ssm_parameter()

        cognito_domain = os.environ.get('COGNITO_DOMAIN')
        region = os.environ.get('AWS_REGION', 'us-west-2')
        cognito_client_id = os.environ.get('COGNITO_CLIENT_ID')
        cognito_client_secret = os.environ.get('COGNITO_CLIENT_SECRET')

        # IMPORTANT: The redirect_uri must match exactly what was used in the authorize request
        # and what is registered in Cognito
        callback_url = f'{os.environ.get("MCP_SERVER_BASE_URL", f"http://localhost:{os.environ['PORT']}")}/callback'

        print(f'Cognito client ID: {cognito_client_id}')
        print(f'Client secret available: {"Yes" if cognito_client_secret else "No"}')
        print(f"MCP Server callback URL for Cognito token exchange: {callback_url}")

        # Make token request to Cognito
        token_url = f'https://{cognito_domain}.auth.{region}.amazoncognito.com/oauth2/token'

        # Create token request data
        form_data = {
            'grant_type': 'authorization_code',
            'client_id': cognito_client_id,
            'code': code,
            'redirect_uri': callback_url,
        }

        print(f'Token request data: {form_data}')

        # Set up the request headers
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        }

        # Import for handling Basic Auth encoding
        import base64

        # Add Authorization header for client authentication
        if cognito_client_secret:
            # Use HTTP Basic Authentication with correct encoding
            auth_string = f'{cognito_client_id}:{cognito_client_secret}'
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            headers['Authorization'] = f'Basic {encoded_auth}'
            print('Using Basic Authentication with client secret')

        # Make the token request
        async with httpx.AsyncClient() as client:
            print('Sending token request to Cognito...')
            token_response = await client.post(
                token_url,
                data=form_data,
                headers=headers,
                timeout=30.0,
            )

            print(f'Token response status: {token_response.status_code}')
            print(f'Token response headers: {token_response.headers}')
            print(f'Token response body: {token_response.text}')

            token_response.raise_for_status()
            tokens = token_response.json()
            print(f'Received tokens: {list(tokens.keys())}')

        # 5. Generate an MCP authorization code
        mcp_auth_code = str(uuid.uuid4())
        print(f'Generated MCP auth code: {mcp_auth_code}')

        # 6. Store the mapping between MCP code and Cognito tokens in DynamoDB
        token_data = {
            'cognito_access_token': tokens['access_token'],
            'cognito_refresh_token': tokens.get('refresh_token'),
            'cognito_id_token': tokens.get('id_token'),
            'client_id': session['client_id'],
            'scope': session['scope'],
            'code_challenge': session['code_challenge'],
            'code_challenge_method': session['code_challenge_method'],
            'created_at': time.time(),
            'expires_in': tokens.get('expires_in', 3600),
        }
        await token_store.store_token_mapping(mcp_auth_code, token_data)

        # 7. Redirect back to the MCP client with the MCP authorization code
        redirect_params = {'code': mcp_auth_code}

        # Include state if it was in the original request
        if session.get('state'):
            redirect_params['state'] = session['state']

        # Build the redirect URL
        redirect_url = session['redirect_uri']
        if '?' in redirect_url:
            redirect_url += '&' + urlencode(redirect_params)
        else:
            redirect_url += '?' + urlencode(redirect_params)

        print(f"Redirecting to MCP client at: {redirect_url}")
        print(f"(This should match the original client redirect_uri: {session['redirect_uri']})")

        # Clean up the session from DynamoDB
        # await token_store.delete_session(state)

        return RedirectResponse(redirect_url, status_code=302)

    except Exception as e:
        print(f'Error exchanging code for tokens: {str(e)}')
        # Get more detailed exception info
        import traceback

        traceback.print_exc()

        return JSONResponse(
            {
                'error': 'server_error',
                'error_description': f'Failed to exchange authorization code for tokens: {str(e)}',
            },
            status_code=500,
        )


# Handle token requests from MCP clients
async def token(request: Request):
    try:
        print('\n==== TOKEN ENDPOINT ENTERED ====')

        # Extract form data
        form_data = await request.form()
        print(f'Complete form data: {dict(form_data)}')

        # Check specifically for redirect_uri
        redirect_uri = form_data.get('redirect_uri')
        print(f'Redirect URI in token request: {redirect_uri}')

        # Compare with registered URIs
        client_id = form_data.get('client_id')
        client = await token_store.get_client(client_id)
        if client:
            registered_redirect_uris = client['redirect_uris']
            print(f'Registered redirect URIs for client {client_id}: {registered_redirect_uris}')
            print(f'Redirect URI match: {redirect_uri in registered_redirect_uris}')

        # 1. Extract and validate token request parameters
        grant_type = form_data.get('grant_type')
        code = form_data.get('code')
        client_id = form_data.get('client_id')
        redirect_uri = form_data.get('redirect_uri')
        code_verifier = form_data.get('code_verifier')
        refresh_token = form_data.get('refresh_token')

        print(f'Token request received: grant_type={grant_type}, client_id={client_id}')

        # Handle different grant types
        if grant_type == 'authorization_code':
            print(f'Processing authorization_code grant with code={code}')
            return await handle_authorization_code_grant(
                code, client_id, redirect_uri, code_verifier
            )
        elif grant_type == 'refresh_token':
            print('Processing refresh_token grant')
            return await handle_refresh_token_grant(refresh_token, client_id)
        else:
            print(f'Unsupported grant type: {grant_type}')
            return JSONResponse(
                {
                    'error': 'unsupported_grant_type',
                    'error_description': f"Grant type '{grant_type}' is not supported",
                },
                status_code=400,
            )

    except Exception as e:
        print(f'Error processing token request: {str(e)}')
        import traceback

        traceback.print_exc()

        return JSONResponse(
            {
                'error': 'server_error',
                'error_description': f'Failed to process token request: {str(e)}',
            },
            status_code=500,
        )


async def handle_authorization_code_grant(code, client_id, redirect_uri, code_verifier):
    """Handle the authorization_code grant type."""
    # Ensure we have the latest base URL
    get_ssm_parameter()

    # 1. Validate required parameters
    if not code or not client_id or not redirect_uri:
        return JSONResponse(
            {
                'error': 'invalid_request',
                'error_description': 'Missing required parameters',
            },
            status_code=400,
        )

    # 2. Retrieve the token mapping for the authorization code from DynamoDB
    token_mapping = await token_store.get_token_mapping(code)
    if not token_mapping:
        return JSONResponse(
            {
                'error': 'invalid_grant',
                'error_description': 'Invalid authorization code',
            },
            status_code=400,
        )

    # 3. Verify the client
    if token_mapping['client_id'] != client_id:
        return JSONResponse(
            {
                'error': 'invalid_grant',
                'error_description': 'Authorization code was issued to another client',
            },
            status_code=400,
        )

    # 4. Verify PKCE if used
    if 'code_challenge' in token_mapping:
        if not code_verifier:
            return JSONResponse(
                {
                    'error': 'invalid_request',
                    'error_description': 'Missing code_verifier',
                },
                status_code=400,
            )

        # Verify the code challenge
        if token_mapping['code_challenge_method'] == 'S256':
            import base64
            import hashlib

            # Calculate the challenge from the verifier
            verifier_bytes = code_verifier.encode('ascii')
            digest = hashlib.sha256(verifier_bytes).digest()
            challenge = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')

            if challenge != token_mapping['code_challenge']:
                return JSONResponse(
                    {
                        'error': 'invalid_grant',
                        'error_description': 'Invalid code_verifier',
                    },
                    status_code=400,
                )

    # 5. Generate MCP access token (and optionally refresh token)
    expires_in = token_mapping.get('expires_in', 3600)
    now = int(time.time())

    # Create claims for the access token
    access_token_claims = {
        'iss': os.environ.get('MCP_SERVER_BASE_URL', f'http://localhost:{os.environ["PORT"]}'),
        'sub': client_id,
        'aud': 'mcp-server',
        'exp': now + expires_in,
        'iat': now,
        'jti': str(uuid.uuid4()),
        'scope': token_mapping['scope'],
        'cognito_token': token_mapping['cognito_access_token'],
        'kid': 'mcp-1',  # This is what validate_token checks for
    }

    # Sign the JWT
    secret_key = os.environ.get('JWT_SECRET_KEY', 'your-secret-key')
    access_token = jwt.encode(
        access_token_claims,
        secret_key,
        algorithm='HS256',
        headers={'kid': 'mcp-1', 'typ': 'JWT'},  # Add the kid to the headers
    )

    # Generate a refresh token if Cognito provided one
    mcp_refresh_token = None
    if 'cognito_refresh_token' in token_mapping:
        mcp_refresh_token = str(uuid.uuid4())

        # Store the refresh token mapping in DynamoDB
        refresh_token_data = {
            'client_id': client_id,
            'cognito_refresh_token': token_mapping['cognito_refresh_token'],
            'scope': token_mapping['scope'],
            'created_at': now,
        }
        await token_store.store_refresh_token(mcp_refresh_token, refresh_token_data)

    # Clean up the used authorization code from DynamoDB
    await token_store.delete_token_mapping(code)

    # Return the token response
    response = {
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': expires_in,
        'scope': token_mapping['scope'],
    }

    if mcp_refresh_token:
        response['refresh_token'] = mcp_refresh_token

    return JSONResponse(response)


async def handle_refresh_token_grant(refresh_token, client_id):
    """Handle the refresh_token grant type."""
    # Ensure we have the latest base URL
    get_ssm_parameter()

    # 1. Validate required parameters
    if not refresh_token or not client_id:
        return JSONResponse(
            {
                'error': 'invalid_request',
                'error_description': 'Missing required parameters',
            },
            status_code=400,
        )

    # 2. Retrieve the refresh token mapping from DynamoDB
    token_mapping = await token_store.get_refresh_token(refresh_token)
    if not token_mapping:
        return JSONResponse(
            {
                'error': 'invalid_grant',
                'error_description': 'Invalid refresh token',
            },
            status_code=400,
        )

    # 3. Verify the client
    if token_mapping['client_id'] != client_id:
        return JSONResponse(
            {
                'error': 'invalid_grant',
                'error_description': 'Refresh token was issued to another client',
            },
            status_code=400,
        )

    # 4. Refresh the Cognito token
    try:
        cognito_domain = os.environ.get('COGNITO_DOMAIN')
        region = os.environ.get('AWS_REGION', 'us-west-2')
        cognito_client_id = os.environ.get('COGNITO_CLIENT_ID')
        cognito_client_secret = os.environ.get('COGNITO_CLIENT_SECRET')

        # Make refresh token request to Cognito
        token_url = f'https://{cognito_domain}.auth.{region}.amazoncognito.com/oauth2/token'
        token_data = {
            'grant_type': 'refresh_token',
            'client_id': cognito_client_id,
            'refresh_token': token_mapping['cognito_refresh_token'],
        }

        # Include client secret if available
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        auth = None
        if cognito_client_secret:
            auth = (cognito_client_id, cognito_client_secret)

        # Make the token request
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                token_url,
                data=token_data,
                headers=headers,
                auth=auth,
                timeout=30.0,
            )
            token_response.raise_for_status()
            tokens = token_response.json()

        # 5. Generate new MCP access token
        expires_in = tokens.get('expires_in', 3600)
        now = int(time.time())

        # Create claims for the access token
        access_token_claims = {
            'iss': os.environ.get('MCP_SERVER_BASE_URL', 'https://mcp.example.com'),
            'sub': client_id,
            'aud': 'mcp-server',
            'exp': now + expires_in,
            'iat': now,
            'jti': str(uuid.uuid4()),
            'scope': token_mapping['scope'],
            'cognito_token': tokens['access_token'],
            'kid': 'mcp-1',  # Key ID to identify this as an MCP token
        }

        # Sign the JWT
        secret_key = os.environ.get('JWT_SECRET_KEY', 'your-secret-key')
        access_token = jwt.encode(
            access_token_claims,
            secret_key,
            algorithm='HS256',
            headers={'kid': 'mcp-1', 'typ': 'JWT'},  # Add the kid to the headers
        )

        # Update the refresh token mapping in DynamoDB if Cognito provided a new refresh token
        if 'refresh_token' in tokens:
            token_mapping['cognito_refresh_token'] = tokens['refresh_token']
            await token_store.update_refresh_token(refresh_token, token_mapping)

        # Return the token response
        response = {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': expires_in,
            'scope': token_mapping['scope'],
        }

        return JSONResponse(response)

    except Exception as e:
        print(f'Error refreshing token: {str(e)}')
        return JSONResponse(
            {
                'error': 'invalid_grant',
                'error_description': 'Failed to refresh the token',
            },
            status_code=400,
        )


async def validate_cognito_token(token):
    """Validate a Cognito access token."""
    region = os.environ.get('AWS_REGION', 'us-west-2')
    user_pool_id = os.environ.get('COGNITO_USER_POOL_ID')
    client_id = os.environ.get('COGNITO_CLIENT_ID')

    # Get the JWKs from Cognito
    jwks_url = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'

    try:
        # Use async HTTP client
        async with httpx.AsyncClient() as client:
            jwks_response = await client.get(jwks_url)
            jwks = jwks_response.json()

        # Get the key ID from the token header
        headers = jwt.get_unverified_header(token)
        kid = headers['kid']

        # Find the correct key
        key = None
        for jwk in jwks['keys']:
            if jwk['kid'] == kid:
                key = jwk
                break

        if not key:
            return False, {}

        # Construct the public key
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))

        # Define expected issuer
        issuer = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}'

        # Verify and decode the token with appropriate options for access tokens
        claims = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            options={'verify_exp': True},
            issuer=issuer,  # Verify the issuer
        )

        # Additional validations for Cognito access tokens
        if claims.get('token_use') != 'access':
            return False, {}

        # For access tokens, client_id is in the 'client_id' claim, not 'aud'
        if claims.get('client_id') != client_id:
            return False, {}

        return True, claims
    except Exception as e:
        print(f'Token validation error: {str(e)}')
        return False, {}


async def validate_token(token):
    """Validate an access token issued by the MCP server.

    This function handles both directly issued tokens and tokens bound to Cognito.
    """
    try:
        print(f'Validating token: {token[:10]}...')

        # First try to decode the token to determine its source
        headers = jwt.get_unverified_header(token)
        print(f'Token headers: {headers}')

        # Check if this is a token issued by your MCP server
        if headers.get('kid') and headers.get('kid').startswith('mcp-'):
            print('Validating as MCP server token')
            # This is your MCP server's token
            secret_key = os.environ.get('JWT_SECRET_KEY', 'your-secret-key')

            # Verify the token
            claims = jwt.decode(
                token,
                secret_key,
                algorithms=['HS256'],
                options={'verify_exp': True},
                audience='mcp-server',
            )

            print(f'Token claims: {claims.keys()}')

            # If this token is bound to a Cognito token, validate the Cognito token too
            if 'cognito_token' in claims:
                cognito_token = claims['cognito_token']
                print('Token is bound to Cognito token, validating Cognito token')
                is_valid_cognito, _ = await validate_cognito_token(cognito_token)

                if not is_valid_cognito:
                    print('Cognito token validation failed')
                    return False, {}

            print('MCP token validation successful')
            return True, claims
        else:
            print('Validating as direct Cognito token')
            return await validate_cognito_token(token)

    except Exception as e:
        print(f'Token validation error: {str(e)}')
        import traceback

        traceback.print_exc()
        return False, {}
