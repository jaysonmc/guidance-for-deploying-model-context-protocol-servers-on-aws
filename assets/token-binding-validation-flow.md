# Token Binding and Validation Flow

This diagram focuses specifically on the token binding and validation aspects of the MCP Server with AWS Cognito integration.

```mermaid
sequenceDiagram
    participant Client as MCP Client
    participant Server as MCP Server
    participant Validator as Token Validator
    participant Cognito as AWS Cognito

    %% After successful OAuth flow, client has an MCP access token
    Note over Client,Server: After successful OAuth authorization flow

    %% MCP Token Structure
    rect rgb(100, 100, 100, 0.4)
        Note over Server: MCP Access Token (JWT)<br>Header: {"alg": "HS256", "kid": "mcp-1"}<br>Payload: {<br>  "iss": "https://mcp-server.example.com",<br>  "sub": "client_id",<br>  "aud": "mcp-server",<br>  "scope": "mcp-server/read mcp-server/write",<br>  "exp": 1649962598,<br>  "iat": 1649958998,<br>  "cognito_token": "{cognito_access_token}"<br>}
    end

    %% API Request with token
    Client->>Server: API Request<br>Authorization: Bearer mcp_token
    
    %% Server validation flow
    Server->>Validator: Validate MCP token
    
    %% Token Validation Steps
    rect rgb(100, 100, 100, 0.4)
        Note over Validator: 1. Verify JWT signature<br>2. Check expiration<br>3. Validate issuer and audience<br>4. Extract embedded Cognito token
    end
    
    %% Cognito token validation
    Validator->>Cognito: Get JWKS<br>/.well-known/jwks.json
    Cognito->>Validator: JSON Web Key Set
    
    rect rgb(100, 100, 100, 0.4)
        Note over Validator: 1. Find matching JWK by kid<br>2. Verify Cognito token signature<br>3. Validate Cognito token claims<br>4. Check token_use = "access"
    end
    
    %% Return validation result
    Validator->>Server: Validation result & claims
    
    alt Valid token
        Server->>Client: 200 OK + API response
    else Invalid token
        Server->>Client: 401 Unauthorized<br>{"error": "invalid_token"}
    end

    %% Token Refresh
    Note over Client,Server: When token expires
    Client->>Server: POST /token<br>grant_type=refresh_token<br>refresh_token=mcp_refresh_token
    
    %% Server refresh flow
    Server->>Cognito: POST /oauth2/token<br>grant_type=refresh_token<br>refresh_token=cognito_refresh_token
    Cognito->>Server: {access_token, refresh_token}

    %% Create new bound token    
    rect rgb(100, 100, 100, 0.4)
        Note over Server: Generate new MCP access token<br>with fresh Cognito token embedded
    end
    
    Server->>Client: {access_token, token_type: "Bearer",<br>expires_in, scope}
