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
# Get base path from environment variable or default to empty string
BASE_PATH = os.environ.get('BASE_PATH', '')
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from urllib.parse import urlencode


class OAuthMiddlewareCognito(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Skip auth for health endpoint
        if (
            request.url.path == f'{BASE_PATH}/'
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
