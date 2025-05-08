"""DynamoDB-based token storage for MCP Server.

Provides persistence layer for OAuth tokens and client registrations.
"""

import asyncio
import boto3
import os
import time
from decimal import Decimal


class DynamoDBTokenStore:
    """DynamoDB-based storage for OAuth tokens and client registrations."""

    def __init__(self):
        """Initialize the token store with DynamoDB client."""
        self.table_name = os.environ.get('TOKEN_TABLE_NAME')
        if not self.table_name:
            raise ValueError('TOKEN_TABLE_NAME environment variable must be set')

        region = os.environ.get('AWS_REGION', 'us-west-2')
        self.dynamodb = boto3.resource('dynamodb', region_name=region)
        self.table = self.dynamodb.Table(self.table_name)
        print(f'Initialized DynamoDBTokenStore with table: {self.table_name}')

    # Client registrations
    async def store_client(self, client_id, client_data):
        """Store client registration in DynamoDB."""
        item = {
            'PK': f'CLIENT#{client_id}',
            'SK': 'CLIENT',
            'data': self._convert_floats(client_data),
            'created_at': int(time.time()),
        }
        await self._put_item(item)
        print(f'Stored client: {client_id}')

    async def get_client(self, client_id):
        """Get client registration from DynamoDB."""
        key = {'PK': f'CLIENT#{client_id}', 'SK': 'CLIENT'}
        response = await self._get_item(key)
        client_data = response.get('Item', {}).get('data')
        print(f'Retrieved client: {client_id} - Found: {client_data is not None}')
        # Convert any Decimal values back to float before returning
        return self.convert_decimals(client_data) if client_data else None

    async def client_exists(self, client_id):
        """Check if client exists."""
        client = await self.get_client(client_id)
        return client is not None

    async def delete_client(self, client_id):
        """Delete client registration."""
        key = {'PK': f'CLIENT#{client_id}', 'SK': 'CLIENT'}
        await self._delete_item(key)
        print(f'Deleted client: {client_id}')

    # Auth sessions
    async def store_session(self, session_id, session_data):
        """Store auth session in DynamoDB."""
        # Add expiration for TTL (24 hours)
        expiration = int(time.time()) + (24 * 60 * 60)
        item = {
            'PK': f'SESSION#{session_id}',
            'SK': 'SESSION',
            'data': self._convert_floats(session_data),
            'created_at': int(time.time()),
            'expiration': expiration,
        }
        await self._put_item(item)
        print(f'Stored session: {session_id}')

    async def get_session(self, session_id):
        """Get auth session from DynamoDB."""
        key = {'PK': f'SESSION#{session_id}', 'SK': 'SESSION'}
        response = await self._get_item(key)
        session_data = response.get('Item', {}).get('data')
        print(f'Retrieved session: {session_id} - Found: {session_data is not None}')
        # Convert any Decimal values back to float before returning
        return self.convert_decimals(session_data) if session_data else None

    async def delete_session(self, session_id):
        """Delete auth session."""
        key = {'PK': f'SESSION#{session_id}', 'SK': 'SESSION'}
        await self._delete_item(key)
        print(f'Deleted session: {session_id}')

    # Token mappings
    async def store_token_mapping(self, auth_code, token_data):
        """Store token mapping in DynamoDB."""
        # Set expiration for 10 minutes (auth codes are short-lived)
        expiration = int(time.time()) + (10 * 60)
        item = {
            'PK': f'TOKEN#{auth_code}',
            'SK': 'TOKEN',
            'data': self._convert_floats(token_data),
            'created_at': int(time.time()),
            'expiration': expiration,
        }
        await self._put_item(item)
        print(f'Stored token mapping for auth code: {auth_code}')

    async def get_token_mapping(self, auth_code):
        """Get token mapping from DynamoDB."""
        key = {'PK': f'TOKEN#{auth_code}', 'SK': 'TOKEN'}
        response = await self._get_item(key)
        token_data = response.get('Item', {}).get('data')
        print(f'Retrieved token mapping: {auth_code} - Found: {token_data is not None}')
        # Convert any Decimal values back to float before returning
        return self.convert_decimals(token_data) if token_data else None

    async def delete_token_mapping(self, auth_code):
        """Delete token mapping."""
        key = {'PK': f'TOKEN#{auth_code}', 'SK': 'TOKEN'}
        await self._delete_item(key)
        print(f'Deleted token mapping for auth code: {auth_code}')

    # Refresh tokens
    async def store_refresh_token(self, refresh_token, token_data):
        """Store refresh token in DynamoDB."""
        # Set expiration for 30 days
        expiration = int(time.time()) + (30 * 24 * 60 * 60)
        item = {
            'PK': f'REFRESH#{refresh_token}',
            'SK': 'REFRESH',
            'data': self._convert_floats(token_data),
            'created_at': int(time.time()),
            'expiration': expiration,
        }
        await self._put_item(item)
        print(f'Stored refresh token: {refresh_token}')

    async def get_refresh_token(self, refresh_token):
        """Get refresh token from DynamoDB."""
        key = {'PK': f'REFRESH#{refresh_token}', 'SK': 'REFRESH'}
        response = await self._get_item(key)
        token_data = response.get('Item', {}).get('data')
        print(f'Retrieved refresh token: {refresh_token} - Found: {token_data is not None}')
        # Convert any Decimal values back to float before returning
        return self.convert_decimals(token_data) if token_data else None

    async def update_refresh_token(self, refresh_token, token_data):
        """Update refresh token data."""
        # Set expiration for 30 days
        expiration = int(time.time()) + (30 * 24 * 60 * 60)
        item = {
            'PK': f'REFRESH#{refresh_token}',
            'SK': 'REFRESH',
            'data': self._convert_floats(token_data),
            'created_at': int(time.time()),
            'expiration': expiration,
        }
        await self._put_item(item)
        print(f'Updated refresh token: {refresh_token}')

    async def delete_refresh_token(self, refresh_token):
        """Delete refresh token."""
        key = {'PK': f'REFRESH#{refresh_token}', 'SK': 'REFRESH'}
        await self._delete_item(key)
        print(f'Deleted refresh token: {refresh_token}')

    # Helper methods for DynamoDB operations
    async def _put_item(self, item):
        """Helper method to put an item in DynamoDB."""
        # Convert to sync operation since boto3 doesn't support async natively
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.table.put_item(Item=item))

    async def _get_item(self, key):
        """Helper method to get an item from DynamoDB."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.table.get_item(Key=key))

    async def _delete_item(self, key):
        """Helper method to delete an item from DynamoDB."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.table.delete_item(Key=key))

    def _convert_floats(self, obj):
        """Recursively convert float values to Decimal for DynamoDB compatibility.

        Used when storing data to DynamoDB
        """
        if isinstance(obj, float):
            return Decimal(str(obj))
        elif isinstance(obj, dict):
            return {k: self._convert_floats(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_floats(i) for i in obj]
        else:
            return obj

    def convert_decimals(self, obj):
        """Recursively convert Decimal values back to float.

        Used when retrieving data from DynamoDB
        """
        if isinstance(obj, Decimal):
            # Convert Decimal to float
            return float(obj)
        elif isinstance(obj, dict):
            # Convert each value in the dictionary
            return {k: self.convert_decimals(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            # Convert each item in the list
            return [self.convert_decimals(v) for v in obj]
        # Return other types unchanged
        return obj
