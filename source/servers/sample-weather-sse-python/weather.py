import httpx
import os
import uvicorn
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport

# Import OAuth handlers
from oauth_cognito import (
    OAuthMiddlewareCognito,
)
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from typing import Any

# Get base path from environment variable or default to empty string
BASE_PATH = os.environ.get('BASE_PATH', '')


# Load environment variables from .env file
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP('weather')

# Constants
NWS_API_BASE = 'https://api.weather.gov'
USER_AGENT = 'weather-app/1.0'

# Create SSE transport
sse = SseServerTransport(f'{BASE_PATH}/messages/')

# MCP SSE handler function
async def handle_sse(request):
    async with sse.connect_sse(request.scope, request.receive, request._send) as (
        read_stream,
        write_stream,
    ):
        await mcp._mcp_server.run(
            read_stream, write_stream, mcp._mcp_server.create_initialization_options()
        )

async def make_nws_request(url: str) -> dict[str, Any] | None:
    """Make a request to the NWS API with proper error handling."""
    headers = {'User-Agent': USER_AGENT, 'Accept': 'application/geo+json'}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception:
            return None


def format_alert(feature: dict) -> str:
    """Format an alert feature into a readable string."""
    props = feature['properties']
    return f"""
Event: {props.get('event', 'Unknown')}
Area: {props.get('areaDesc', 'Unknown')}
Severity: {props.get('severity', 'Unknown')}
Description: {props.get('description', 'No description available')}
Instructions: {props.get('instruction', 'No specific instructions provided')}
"""


@mcp.tool()
async def get_alerts(state: str) -> str:
    """Get weather alerts for a US state.

    Args:
        state: Two-letter US state code (e.g. CA, NY)
    """
    url = f'{NWS_API_BASE}/alerts/active/area/{state}'
    data = await make_nws_request(url)

    if not data or 'features' not in data:
        return 'Unable to fetch alerts or no alerts found.'

    if not data['features']:
        return 'No active alerts for this state.'

    alerts = [format_alert(feature) for feature in data['features']]
    return '\n---\n'.join(alerts)


@mcp.tool()
async def get_forecast(latitude: float, longitude: float) -> str:
    """Get weather forecast for a location.

    Args:
        latitude: Latitude of the location
        longitude: Longitude of the location
    """
    # First get the forecast grid endpoint
    points_url = f'{NWS_API_BASE}/points/{latitude},{longitude}'
    points_data = await make_nws_request(points_url)

    if not points_data:
        return 'Unable to fetch forecast data for this location.'

    # Get the forecast URL from the points response
    forecast_url = points_data['properties']['forecast']
    forecast_data = await make_nws_request(forecast_url)

    if not forecast_data:
        return 'Unable to fetch detailed forecast.'

    # Format the periods into a readable forecast
    periods = forecast_data['properties']['periods']
    forecasts = []
    for period in periods[:5]:  # Only show next 5 periods
        forecast = f"""
{period['name']}:
Temperature: {period['temperature']}°{period['temperatureUnit']}
Wind: {period['windSpeed']} {period['windDirection']}
Forecast: {period['detailedForecast']}
"""
        forecasts.append(forecast)

    return '\n---\n'.join(forecasts)


# Add a health check route handler
async def health_check(request):
    return JSONResponse({'status': 'healthy', 'service': 'weather-api-python'})


if __name__ == '__main__':
    # For simplicity, let's use the built-in run method
    # This automatically sets up both the SSE and message endpoints
    port = int(os.environ.get('PORT', 3000))

    # Create a custom Starlette app that includes our health check
    # AND properly integrates with the MCP SSE implementation
    sse_app = mcp.sse_app()

    # Create our custom app with both the health check and the OAuth endpoints
    app = Starlette(
        routes=[
            Route(f'{BASE_PATH}/', health_check),
            Route(f'{BASE_PATH}/sse', endpoint=handle_sse),
            Mount(f'{BASE_PATH}/messages/', app=sse.handle_post_message),
        ],
        middleware=[Middleware(OAuthMiddlewareCognito)],
    )

    print(f'Starting MCP weather server on port {port}. Press CTRL+C to exit.')

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
