# MCP Server with AWS Cognito OAuth Flow

This diagram illustrates the OAuth 2.0 authorization code flow between the MCP Client, MCP Server, and AWS Cognito as the third-party authentication provider.

```mermaid
sequenceDiagram
    participant User as User-Agent (Browser)
    participant Client as MCP Client
    participant Server as MCP Server
    participant Cognito as AWS Cognito

    %% Initial OAuth Request
    Client->>Server: Initial OAuth Request
    Note right of Server: Client requests authorization

    %% Redirect to Cognito
    Server->>User: Redirect to AWS Cognito /authorize
    Note right of User: Server stores session state

    %% User Authentication with Cognito
    User->>Cognito: Authorization Request
    Note right of Cognito: User authenticates with Cognito

    %% User Authorizes
    rect rgb(100, 100, 100, 0.4)
        Note over Cognito: User authorizes application
    end

    %% Callback to MCP Server
    Cognito->>User: Redirect to MCP Server callback
    User->>Server: Authorization code

    %% Exchange code for Cognito tokens
    Server->>Cognito: Exchange code for token
    Cognito->>Server: Cognito access/refresh/ID tokens
    
    %% Generate MCP bound token
    rect rgb(100, 100, 100, 0.4)
        Note over Server: Generate bound MCP token
    end

    %% Send MCP code to client
    Server->>User: Redirect to MCP Client callback
    User->>Client: MCP authorization code

    %% Client exchanges code for token
    Client->>Server: Exchange code for MCP token
    Server->>Client: MCP access token

    %% Token Usage
    Note over Client,Server: Client uses MCP token for API calls
