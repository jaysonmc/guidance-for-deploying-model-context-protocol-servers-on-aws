import httpx
import os
import uvicorn
from dotenv import load_dotenv

# Import OAuth handlers
from oauth_cognito import (
    OAuthMiddlewareCognito,
    authorize,
    callback,
    oauth_metadata,
    register_client,
    token,
)
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from typing import Any


# Load environment variables from .env file
load_dotenv()

# Add a health check route handler
async def health_check(request):
    return JSONResponse({'status': 'healthy', 'service': 'auth-api'})


if __name__ == '__main__':
    # For simplicity, let's use the built-in run method
    # This automatically sets up both the SSE and message endpoints
    port = int(os.environ.get('PORT', 2299))

    # Create our custom app with both the health check and the OAuth endpoints
    app = Starlette(
        routes=[
            Route('/', health_check),
            Route('/.well-known/oauth-authorization-server', oauth_metadata),
            Route('/register', register_client, methods=['POST']),
            Route('/authorize', authorize),
            Route('/callback', callback),
            Route('/token', token, methods=['POST']),
        ],
        middleware=[Middleware(OAuthMiddlewareCognito)],
    )

    print(f'Starting MCP auth server on port {port}. Press CTRL+C to exit.')

    # Run the combined app with a short timeout for graceful shutdown
    # This ensures CTRL+C exits quickly without hanging
    
    # For container environments like Fargate/ECS, we need to bind to 0.0.0.0
    # This is accepted as a necessary risk for containerized deployments
    # nosec B104 - Binding to all interfaces is required for container environments
    uvicorn.run(
        app,
        host='0.0.0.0',  # nosec B104
        port=port,
        timeout_graceful_shutdown=2,  # Only wait 2 seconds for connections to close
    )
