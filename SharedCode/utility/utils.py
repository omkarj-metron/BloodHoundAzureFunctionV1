import os
import logging
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError

def fetch_env_variables(required_vars):
    """
    Fetches all required environment variables and returns a dict.
    Logs and raises KeyError if any are missing.
    """
    env = {}
    missing = []
    for var in required_vars:
        value = os.environ.get(var)
        if value is None:
            missing.append(var)
        env[var] = value
    if missing:
        logging.error(f"Missing required environment variables: {', '.join(missing)}")
        raise KeyError(f"Missing required environment variables: {', '.join(missing)}")
    return env

def fetch_key_vault_secrets(key_vault_url, token_ids_secret_name, token_keys_secret_name):
    """
    Fetches token IDs and token keys from Azure Key Vault.
    Returns two lists: all_token_ids, all_token_keys.
    Raises and logs errors if secrets are missing or retrieval fails.
    """
    try:
        credential = DefaultAzureCredential()
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)
        token_ids = secret_client.get_secret(token_ids_secret_name).value
        token_keys = secret_client.get_secret(token_keys_secret_name).value
        all_token_ids = [token_id.strip() for token_id in token_ids.split(',')]
        all_token_keys = [token_key.strip() for token_key in token_keys.split(',')]
        logging.info("Successfully retrieved all API tokens from Azure Key Vault.")
        return all_token_ids, all_token_keys
    except ResourceNotFoundError as e:
        logging.error(f"One or more secrets not found in Azure Key Vault: {e}. Ensure all secrets exist. Exiting process.")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred while retrieving secrets from Azure Key Vault: {e}. Exiting process.")
        raise

def get_token_lists(key_vault_url=None, token_ids_secret_name=None, token_keys_secret_name=None):
    """
    Returns all_token_ids and all_token_keys from Key Vault using provided names and URL.
    Raises ValueError if insufficient information is provided.
    """
    if key_vault_url and token_ids_secret_name and token_keys_secret_name:
        return fetch_key_vault_secrets(key_vault_url, token_ids_secret_name, token_keys_secret_name)
    else:
        logging.error("Insufficient information to fetch token IDs and keys from Key Vault.")
        raise ValueError("Insufficient information to fetch token IDs and keys from Key Vault.")
