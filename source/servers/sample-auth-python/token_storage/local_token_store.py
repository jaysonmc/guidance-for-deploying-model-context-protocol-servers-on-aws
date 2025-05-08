"""In-memory token storage for MCP Server.

For local development or when DynamoDB is not configured.
"""

import time


class LocalTokenStore:
    """In-memory storage for OAuth tokens and client registrations."""

    def __init__(self):
        """Initialize the in-memory token store."""
        self.clients = {}
        self.sessions = {}
        self.tokens = {}
        self.refresh_tokens = {}
        print('Initialized LocalTokenStore with in-memory storage')

    # Client registrations
    async def store_client(self, client_id, client_data):
        """Store client registration in memory."""
        self.clients[client_id] = {
            'data': client_data,
            'created_at': int(time.time()),
        }
        print(f'Stored client: {client_id}')

    async def get_client(self, client_id):
        """Get client registration from memory."""
        client_entry = self.clients.get(client_id)
        client_data = client_entry['data'] if client_entry else None
        print(f'Retrieved client: {client_id} - Found: {client_data is not None}')
        return client_data

    async def client_exists(self, client_id):
        """Check if client exists."""
        client = await self.get_client(client_id)
        return client is not None

    async def delete_client(self, client_id):
        """Delete client registration."""
        if client_id in self.clients:
            del self.clients[client_id]
            print(f'Deleted client: {client_id}')

    # Auth sessions
    async def store_session(self, session_id, session_data):
        """Store auth session in memory."""
        # Add expiration for TTL (24 hours)
        expiration = int(time.time()) + (24 * 60 * 60)
        self.sessions[session_id] = {
            'data': session_data,
            'created_at': int(time.time()),
            'expiration': expiration,
        }
        print(f'Stored session: {session_id}')

    async def get_session(self, session_id):
        """Get auth session from memory with expiration check."""
        session_entry = self.sessions.get(session_id)

        # Check if session exists and if it has expired
        if session_entry:
            if session_entry.get('expiration') and session_entry['expiration'] < int(time.time()):
                # Session expired, remove it
                del self.sessions[session_id]
                print(f'Session {session_id} expired and removed')
                return None

            print(f'Retrieved session: {session_id} - Found: True')
            return session_entry['data']

        print(f'Retrieved session: {session_id} - Found: False')
        return None

    async def delete_session(self, session_id):
        """Delete auth session."""
        if session_id in self.sessions:
            del self.sessions[session_id]
            print(f'Deleted session: {session_id}')

    # Token mappings
    async def store_token_mapping(self, auth_code, token_data):
        """Store token mapping in memory."""
        # Set expiration for 10 minutes (auth codes are short-lived)
        expiration = int(time.time()) + (10 * 60)
        self.tokens[auth_code] = {
            'data': token_data,
            'created_at': int(time.time()),
            'expiration': expiration,
        }
        print(f'Stored token mapping for auth code: {auth_code}')

    async def get_token_mapping(self, auth_code):
        """Get token mapping from memory with expiration check."""
        token_entry = self.tokens.get(auth_code)

        # Check if token exists and if it has expired
        if token_entry:
            if token_entry.get('expiration') and token_entry['expiration'] < int(time.time()):
                # Token expired, remove it
                del self.tokens[auth_code]
                print(f'Token {auth_code} expired and removed')
                return None

            print(f'Retrieved token mapping: {auth_code} - Found: True')
            return token_entry['data']

        print(f'Retrieved token mapping: {auth_code} - Found: False')
        return None

    async def delete_token_mapping(self, auth_code):
        """Delete token mapping."""
        if auth_code in self.tokens:
            del self.tokens[auth_code]
            print(f'Deleted token mapping for auth code: {auth_code}')

    # Refresh tokens
    async def store_refresh_token(self, refresh_token, token_data):
        """Store refresh token in memory."""
        # Set expiration for 30 days
        expiration = int(time.time()) + (30 * 24 * 60 * 60)
        self.refresh_tokens[refresh_token] = {
            'data': token_data,
            'created_at': int(time.time()),
            'expiration': expiration,
        }
        print(f'Stored refresh token: {refresh_token}')

    async def get_refresh_token(self, refresh_token):
        """Get refresh token from memory with expiration check."""
        token_entry = self.refresh_tokens.get(refresh_token)

        # Check if token exists and if it has expired
        if token_entry:
            if token_entry.get('expiration') and token_entry['expiration'] < int(time.time()):
                # Token expired, remove it
                del self.refresh_tokens[refresh_token]
                print(f'Refresh token {refresh_token} expired and removed')
                return None

            print(f'Retrieved refresh token: {refresh_token} - Found: True')
            return token_entry['data']

        print(f'Retrieved refresh token: {refresh_token} - Found: False')
        return None

    async def update_refresh_token(self, refresh_token, token_data):
        """Update refresh token data."""
        # Set expiration for 30 days
        expiration = int(time.time()) + (30 * 24 * 60 * 60)
        self.refresh_tokens[refresh_token] = {
            'data': token_data,
            'created_at': int(time.time()),
            'expiration': expiration,
        }
        print(f'Updated refresh token: {refresh_token}')

    async def delete_refresh_token(self, refresh_token):
        """Delete refresh token."""
        if refresh_token in self.refresh_tokens:
            del self.refresh_tokens[refresh_token]
            print(f'Deleted refresh token: {refresh_token}')

    # Helper methods for API compatibility with DynamoDBTokenStore
    def _convert_floats(self, obj):
        """No-op method for compatibility with DynamoDBTokenStore.
        LocalTokenStore doesn't need to convert floats to Decimal.
        """
        return obj

    def convert_decimals(self, obj):
        """No-op method for compatibility with DynamoDBTokenStore.
        LocalTokenStore doesn't have Decimal values to convert.
        """
        return obj
