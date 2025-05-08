# AWS Cognito Integration with MCP Server

This diagram illustrates the technical architecture of AWS Cognito integration with MCP servers for third-party OAuth authentication.

```mermaid
flowchart TD
    %% Client and User Agent
    User["User-Agent (Browser)"]
    Client["MCP Client"]
    
    %% MCP Server Components
    subgraph "MCP Server on AWS"
        CloudFront["AWS CloudFront\nHTTPS Distribution"]
        ALB["Application Load Balancer"]
        ECS["ECS Fargate Cluster"]
        
        subgraph "MCP Server Container"
            MCPAuth["OAuth Endpoints\n/authorize\n/callback\n/token"]
            MCPTools["MCP Tools & Resources"]
        end
        
        %% Container connections
        MCPAuth --- MCPTools
    end
    
    %% AWS Cognito Components
    subgraph "AWS Cognito"
        UserPool["Cognito User Pool"]
        AppClient["App Client\nwith OIDC scopes"]
        Domain["Cognito Domain\n{prefix}.auth.{region}.amazoncognito.com"]
        
        %% Cognito internal connections
        UserPool --- AppClient
        UserPool --- Domain
    end
    
    %% AWS Supporting Services
    subgraph "Supporting AWS Services"
        SSM["SSM Parameter Store\n- HTTPS URLs\n- User Pool IDs"]
        WAF["AWS WAF"]
    end

    %% External connections
    User <--> Client
    User <--> CloudFront
    User <--> Domain
    
    %% AWS Architecture flow
    Client <--> CloudFront
    CloudFront <--> ALB
    ALB <--> ECS
    WAF -.-> CloudFront
    WAF -.-> ALB
    
    %% Authentication flow
    MCPAuth <--> UserPool
    MCPAuth -..-> SSM
    ECS -..-> SSM

    %% CDK Deployment components
    subgraph "CDK Deployment"
        SecurityStack["Security Stack\n- User Pool\n- WAF"]
        MCPServerStack["MCP Server Stack\n- Fargate Service\n- CloudFront"]
        CrossRegionSync["Cross-Region\nParameter Sync"]
        
        SecurityStack --> MCPServerStack
        SecurityStack --> CrossRegionSync
    end

    %% Environment Variables Configuration
    subgraph "Container Environment"
        EnvVars["Environment Variables\n- COGNITO_USER_POOL_ID\n- COGNITO_CLIENT_ID\n- COGNITO_CLIENT_SECRET\n- COGNITO_DOMAIN"]
    end
    
    MCPServerStack --> EnvVars
    EnvVars --> MCPAuth
    
    %% Legend
    classDef aws fill:#FF9900,stroke:#232F3E,color:white
    classDef mcp fill:#1D3557,stroke:#457B9D,color:white
    class UserPool,AppClient,Domain,CloudFront,ALB,ECS,SSM,WAF,CrossRegionSync aws
    class MCPAuth,MCPTools,Client aws
    
    %% Style for CDK stacks
    classDef cdkStack fill:#232F3E,stroke:#FF9900,color:white
    class SecurityStack,MCPServerStack cdkStack
