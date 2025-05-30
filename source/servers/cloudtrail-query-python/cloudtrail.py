import os
import uvicorn
import boto3
from datetime import datetime, timedelta
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route, Mount
from typing import Any, List, Optional

# Get base path from environment variable or default to empty string
BASE_PATH = os.environ.get('BASE_PATH', '')

# Load environment variables from .env file
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP('cloudtrail')

# Create CloudTrail client
def get_cloudtrail_client():
    """Create and return a boto3 CloudTrail client."""
    return boto3.client('cloudtrail')

@mcp.tool()
async def get_recent_events(minutes: int = 1, event_name: Optional[str] = None) -> str:
    """Get recent CloudTrail events.

    Args:
        minutes: Number of minutes to look back (default: 1)
        event_name: Optional filter for specific event name
    """
    try:
        # Calculate start and end time
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=minutes)
        
        # Create CloudTrail client
        client = get_cloudtrail_client()
        
        # Prepare lookup attributes if event_name is provided
        lookup_attributes = []
        if event_name:
            lookup_attributes.append({
                'AttributeKey': 'EventName',
                'AttributeValue': event_name
            })
        
        # Make the API call
        kwargs = {
            'StartTime': start_time,
            'EndTime': end_time,
            'MaxResults': 50  # Limit to 50 results
        }
        
        if lookup_attributes:
            kwargs['LookupAttributes'] = lookup_attributes
            
        response = client.lookup_events(**kwargs)
        
        # Format the response
        if not response.get('Events'):
            return f"No CloudTrail events found in the last {minutes} minute(s)."
        
        formatted_events = []
        for event in response['Events']:
            event_time = event.get('EventTime', '').strftime('%Y-%m-%d %H:%M:%S') if isinstance(event.get('EventTime'), datetime) else str(event.get('EventTime', ''))
            formatted_event = f"""
Event Name: {event.get('EventName', 'Unknown')}
Event Time: {event_time}
Username: {event.get('Username', 'N/A')}
Source IP: {event.get('SourceIPAddress', 'N/A')}
Event ID: {event.get('EventId', 'N/A')}
"""
            formatted_events.append(formatted_event)
        
        return '\n---\n'.join(formatted_events)
    
    except Exception as e:
        return f"Error retrieving CloudTrail events: {str(e)}"

@mcp.tool()
async def search_events_by_user(username: str, hours: int = 24) -> str:
    """Search CloudTrail events by username.

    Args:
        username: Username to search for
        hours: Number of hours to look back (default: 24)
    """
    try:
        # Calculate start and end time
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        # Create CloudTrail client
        client = get_cloudtrail_client()
        
        # Prepare lookup attributes
        lookup_attributes = [{
            'AttributeKey': 'Username',
            'AttributeValue': username
        }]
        
        # Make the API call
        response = client.lookup_events(
            LookupAttributes=lookup_attributes,
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50  # Limit to 50 results
        )
        
        # Format the response
        if not response.get('Events'):
            return f"No CloudTrail events found for user '{username}' in the last {hours} hour(s)."
        
        formatted_events = []
        for event in response['Events']:
            event_time = event.get('EventTime', '').strftime('%Y-%m-%d %H:%M:%S') if isinstance(event.get('EventTime'), datetime) else str(event.get('EventTime', ''))
            formatted_event = f"""
Event Name: {event.get('EventName', 'Unknown')}
Event Time: {event_time}
Source IP: {event.get('SourceIPAddress', 'N/A')}
Event ID: {event.get('EventId', 'N/A')}
"""
            formatted_events.append(formatted_event)
        
        return '\n---\n'.join(formatted_events)
    
    except Exception as e:
        return f"Error searching CloudTrail events: {str(e)}"

@mcp.tool()
async def search_events_by_resource(resource_name: str, hours: int = 24) -> str:
    """Search CloudTrail events by resource name.

    Args:
        resource_name: Resource name to search for
        hours: Number of hours to look back (default: 24)
    """
    try:
        # Calculate start and end time
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        # Create CloudTrail client
        client = get_cloudtrail_client()
        
        # Prepare lookup attributes
        lookup_attributes = [{
            'AttributeKey': 'ResourceName',
            'AttributeValue': resource_name
        }]
        
        # Make the API call
        response = client.lookup_events(
            LookupAttributes=lookup_attributes,
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=50  # Limit to 50 results
        )
        
        # Format the response
        if not response.get('Events'):
            return f"No CloudTrail events found for resource '{resource_name}' in the last {hours} hour(s)."
        
        formatted_events = []
        for event in response['Events']:
            event_time = event.get('EventTime', '').strftime('%Y-%m-%d %H:%M:%S') if isinstance(event.get('EventTime'), datetime) else str(event.get('EventTime', ''))
            formatted_event = f"""
Event Name: {event.get('EventName', 'Unknown')}
Event Time: {event_time}
Username: {event.get('Username', 'N/A')}
Source IP: {event.get('SourceIPAddress', 'N/A')}
Event ID: {event.get('EventId', 'N/A')}
"""
            formatted_events.append(formatted_event)
        
        return '\n---\n'.join(formatted_events)
    
    except Exception as e:
        return f"Error searching CloudTrail events: {str(e)}"

# Add health check route handlers
async def health_check(request):
    """Health check endpoint for the service."""
    return JSONResponse({'status': 'healthy', 'service': 'cloudtrail-query-python'})

async def root_health_check(request):
    """Root health check endpoint for container health checks."""
    return JSONResponse({'status': 'healthy', 'service': 'cloudtrail-query-python'})

async def cloudtrail_health_check(request):
    """Specific health check endpoint for CloudTrail Python service."""
    return JSONResponse({'status': 'healthy', 'service': 'cloudtrail-query-python'})

if __name__ == '__main__':
    # For simplicity, let's use the built-in run method
    port = int(os.environ.get('PORT', 3000))

    # Create our custom app with the health check
    app = Starlette(
        routes=[
            Route(f'{BASE_PATH}/', health_check),
            # Add a root path health check for container health checks
            Route('/', root_health_check),
            # Add specific health check path that matches the CDK configuration
            Route('/cloudtrail-python/', cloudtrail_health_check),
            # Mount the MCP server to handle tool endpoints
            Mount(f'{BASE_PATH}/messages/', app=mcp.streamable_http_app()),
        ],
    )

    print(f'Starting MCP CloudTrail query server on port {port}. Press CTRL+C to exit.')
    
    # For container environments like Fargate/ECS, we need to bind to 0.0.0.0
    # This is accepted as a necessary risk for containerized deployments
    # nosec B104 - Binding to all interfaces is required for container environments
    uvicorn.run(
        app,
        host='0.0.0.0',  # nosec B104
        port=port,
        timeout_graceful_shutdown=2,  # Only wait 2 seconds for connections to close
    )
