# Detailed MCP Server with AWS Cognito OAuth Flow

This diagram provides a comprehensive view of the OAuth 2.0 authorization code flow between the User-Agent (browser), MCP Client, MCP Server, and AWS Cognito as the third-party authentication provider.

```mermaid
sequenceDiagram
    participant User as User-Agent (Browser)
    participant Client as MCP Client
    participant Server as MCP Server
    participant Cognito as AWS Cognito

    %% Client registration (one-time setup)
    Note over Client,Server: Client registration (one-time setup)
    Client->>Server: POST /register<br>{redirect_uris, client_name, etc.}
    Server->>Client: {client_id, client_secret}

    %% Start of OAuth flow
    Client->>Server: GET /authorize<br>?client_id=client_id<br>&redirect_uri=callback_url<br>&response_type=code<br>&state=state<br>&code_challenge=challenge
    Note right of Server: Server generates session_id<br>and stores original request

    %% Redirect to Cognito
    Server->>User: HTTP 302 to Cognito<br>/oauth2/authorize<br>?client_id=cognito_client_id<br>&response_type=code<br>&redirect_uri=server_callback<br>&state=session_id
    
    %% User authentication with Cognito
    User->>Cognito: Authorization Request
    Note right of Cognito: User enters credentials<br>and authenticates

    %% User authorizes
    rect rgb(100, 100, 100, 0.4)
        Note over User,Cognito: User authorizes application access
    end

    %% Callback to MCP Server with Cognito code
    Cognito->>User: HTTP 302 to MCP Server<br>/callback?code=cognito_code<br>&state=session_id
    User->>Server: GET /callback?code=cognito_code&state=session_id
    
    %% Server exchanges Cognito code for tokens
    Server->>Cognito: POST /oauth2/token<br>grant_type=authorization_code<br>code=cognito_code<br>client_id=cognito_client_id<br>redirect_uri=server_callback
    Cognito->>Server: {access_token, refresh_token, id_token}
    
    %% Server generates MCP code
    rect rgb(100, 100, 100, 0.4)
        Note over Server: Generate MCP authorization code<br>Store mapping between MCP code<br>and Cognito tokens
    end

    %% Redirect back to client with MCP code
    Server->>User: HTTP 302 to Client<br>redirect_uri?code=mcp_code&state=state
    User->>Client: GET redirect_uri?code=mcp_code&state=state

    %% Client exchanges MCP code for token
    Client->>Server: POST /token<br>grant_type=authorization_code<br>code=mcp_code<br>client_id=client_id<br>redirect_uri=callback_url<br>code_verifier=verifier
    
    %% Server validates and returns MCP token
    rect rgb(100, 100, 100, 0.4)
        Note over Server: Validate code and code_verifier<br>Generate JWT with embedded Cognito token<br>{"iss": "mcp-server", "sub": client_id,<br>"cognito_token": cognito_token, ...}
    end
    
    Server->>Client: {access_token, token_type: "Bearer",<br>expires_in, refresh_token, scope}

    %% API calls with token
    Client->>Server: API Request<br>Authorization: Bearer mcp_token
    
    rect rgb(100, 100, 100, 0.4)
        Note over Server: Validate MCP token<br>Extract and validate Cognito token
    end
    
    Server->>Client: API Response

    %% Token refresh flow
    Note over Client,Server: When token expires
    Client->>Server: POST /token<br>grant_type=refresh_token<br>refresh_token=mcp_refresh_token<br>client_id=client_id
    
    Server->>Cognito: POST /oauth2/token<br>grant_type=refresh_token<br>refresh_token=cognito_refresh_token<br>client_id=cognito_client_id
    Cognito->>Server: {access_token, refresh_token}
    
    rect rgb(100, 100, 100, 0.4)
        Note over Server: Generate new MCP access token<br>with new Cognito token
    end
    
