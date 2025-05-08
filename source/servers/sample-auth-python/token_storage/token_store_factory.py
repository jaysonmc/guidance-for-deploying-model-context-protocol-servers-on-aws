"""Factory module for token store selection.

Automatically selects appropriate token store based on environment configuration.
"""

import os

# Import both token store implementations
from .dynamo_db_token_store import DynamoDBTokenStore
from .local_token_store import LocalTokenStore
from typing import Union


def get_token_store() -> Union[DynamoDBTokenStore, LocalTokenStore]:
    """Factory function to get the appropriate token store implementation based on environment configuration.

    Returns:
        Either DynamoDBTokenStore if TOKEN_TABLE_NAME is set,
        or LocalTokenStore for local development.
    """
    table_name = os.environ.get('TOKEN_TABLE_NAME')

    if table_name:
        try:
            # Try to initialize the DynamoDB token store
            token_store = DynamoDBTokenStore()
            print(f'Using DynamoDB token store with table: {table_name}')
            return token_store
        except Exception as e:
            print(f'Error initializing DynamoDB token store: {e}')
            print('Falling back to local token store...')
            return LocalTokenStore()
    else:
        # No DynamoDB table configured, use local token store
        print('No TOKEN_TABLE_NAME environment variable found')
        print('Using local in-memory token store for development')
        return LocalTokenStore()
