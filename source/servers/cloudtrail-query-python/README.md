# CloudTrail Query MCP Server

This is a Model Context Protocol (MCP) server that provides tools for querying AWS CloudTrail events.

## Features

The server provides the following MCP tools:

- `get_recent_events`: Get CloudTrail events from the last N minutes
- `search_events_by_user`: Search CloudTrail events by username
- `search_events_by_resource`: Search CloudTrail events by resource name

## Requirements

- Python 3.10 or higher
- AWS credentials configured with appropriate CloudTrail permissions
- Docker (for containerized deployment)

## Local Development

1. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install uv
   uv pip install -r pyproject.toml
   ```

3. Run the server:
   ```bash
   python cloudtrail.py
   ```

## Docker Deployment

1. Build the container:
   ```bash
   docker build -t cloudtrail-query-mcp .
   ```

2. Run the container:
   ```bash
   docker run -p 8080:8080 \
     -e AWS_ACCESS_KEY_ID=your_access_key \
     -e AWS_SECRET_ACCESS_KEY=your_secret_key \
     -e AWS_REGION=your_region \
     cloudtrail-query-mcp
   ```

## AWS Permissions

The server requires the following AWS permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage Examples

1. Get recent events from the last 5 minutes:
   ```python
   result = await get_recent_events(minutes=5)
   ```

2. Search events by username:
   ```python
   result = await search_events_by_user(username="admin", hours=24)
   ```

3. Search events by resource:
   ```python
   result = await search_events_by_resource(resource_name="my-bucket", hours=12)
   ```
