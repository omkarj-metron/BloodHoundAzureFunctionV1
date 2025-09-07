import logging
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from azure.core.exceptions import ResourceNotFoundError

from ..utility.utils import (
    EnvironmentConfig,
    AzureConfig,
    load_environment_configs
)
from ..utility.bloodhound_manager import BloodhoundManager

@dataclass
class TierZeroAsset:
    """Represents a tier zero asset to be sent to Azure Monitor."""
    node_id: str
    name: str
    domain_name: str
    data: Dict[str, Any]


def send_tier_zero_assets_to_azure_monitor(
    assets: List[TierZeroAsset],
    bloodhound_manager: BloodhoundManager, 
    azure_monitor_token: str,
    current_tenant_domain: str,
    filtered_domains: List[Dict[str, Any]]
) -> Tuple[int, int]:
    """
    Sends tier zero assets data to Azure Monitor.

    Args:
        assets: List of tier zero assets to send
        bloodhound_manager: The configured BloodHound manager instance
        azure_monitor_token: Valid Azure Monitor bearer token
        current_tenant_domain: The current tenant domain being processed
        filtered_domains: List of filtered domain data
        batch_size: Maximum number of assets to send at once

    Returns:
        Tuple of (successful_submissions, failed_submissions)
    """
    successful_submissions = 0
    failed_submissions = 0

    if not assets:
        logging.info("No Tier Zero Assets data to send to Azure Monitor for this environment.")
        return successful_submissions, failed_submissions

    for idx, asset in enumerate(assets, 1):
        logging.info(f"Sending Tier Zero Asset data {idx}/{len(assets)}: ID {asset.node_id} ({asset.name})")
        # Format data for submission
        data = {
            "data": {
                "nodes": {
                    "0": {
                        "nodeId": asset.node_id,
                        "domain_name": asset.domain_name,
                        "name": asset.name,
                        **asset.data
                    }
                }
            },
            "tenant_domain": current_tenant_domain,
            "collected_domains": filtered_domains
        }

        response = bloodhound_manager.send_tier_zero_assets_data(
            data, azure_monitor_token, domains_data=filtered_domains
        )

        if response and response.get("status") == "success":
            successful_submissions += 1
            logging.info(f"Successfully sent Tier Zero Asset ID {asset.node_id}")
        else:
            failed_submissions += 1
            error_msg = response.get("message", "Unknown error") if response else "No response"
            logging.error(f"Failed to send Tier Zero Asset ID {asset.node_id}: {error_msg}")
        
        time.sleep(0.1)  # Rate limiting between requests

    logging.info(
        f"Tier Zero Asset processing for '{current_tenant_domain}' complete. Successful: {successful_submissions}, Failed: {failed_submissions}."
    )
    return successful_submissions, failed_submissions

def filter_domains(
    domains_data: List[Dict[str, Any]], 
    selected_environments: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Filter domains based on collection status and selected environments.
    
    Args:
        domains_data: List of domains from BloodHound API
        selected_environments: Optional list of environment names to filter by

    Returns:
        List of filtered domain data
    """
    # First filter by collection status
    filtered = [domain for domain in domains_data if domain.get("collected") is True]

    # Then filter by selected environments if specified
    if selected_environments:
        logging.info(f"Filtering domains by selected environments: {', '.join(selected_environments)}")
        filtered = [
            domain for domain in filtered
            if domain.get("name", "").lower() in [env.lower() for env in selected_environments]
        ]
        if not filtered:
            logging.warning("No domains match the selected environments filter")
            return []

    return filtered


def collect_tier_zero_assets(
    bloodhound_manager: BloodhoundManager,
    filtered_domains: List[Dict[str, Any]]
) -> List[TierZeroAsset]:
    """
    Collect tier zero assets for the given domains.
    
    Args:
        bloodhound_manager: Configured BloodHound manager instance
        filtered_domains: List of filtered domain data

    Returns:
        List of tier zero assets
    """
    cypher_response = bloodhound_manager.fetch_tier_zero_assets()

    if (
        not cypher_response
        or "data" not in cypher_response
        or "nodes" not in cypher_response["data"]
    ):
        logging.error("Failed to fetch tier zero assets or received unexpected response structure")
        return []

    assets = []
    for node_id, node_data in cypher_response["data"]["nodes"].items():
        # Exclude 'Meta' kind nodes
        if node_data.get("kind") == "Meta":
            continue

        properties = node_data.get("properties", {})
        name = bloodhound_manager.extract_name(node_data, properties, node_id)
        domain_name = bloodhound_manager.extract_domain_name(
            node_data, properties, name, filtered_domains
        )

        # Create a combined data dictionary
        data = {
            "nodeId": node_id,
            "domain_name": domain_name,
            "name": name,
            **node_data,
        }

        assets.append(TierZeroAsset(
            node_id=node_id,
            name=name,
            domain_name=domain_name,
            data=data
        ))

    return assets


def process_environment(
    env_config: EnvironmentConfig,
    azure_config: AzureConfig,
    logger: Optional[Any] = None
) -> bool:
    """
    Process tier zero assets for a single environment.
    
    Args:
        env_config: Configuration for the BloodHound environment
        azure_config: Azure configuration settings
        logger: Optional logger instance

    Returns:
        True if processing was successful
    """
    # Initialize BloodhoundManager
    bloodhound_manager = BloodhoundManager(
        env_config.tenant_domain,
        env_config.token_id,
        env_config.token_key,
        logger=logger or logging
    )
    bloodhound_manager.set_azure_monitor_config(
        azure_config.tenant_id,
        azure_config.app_id,
        azure_config.app_secret,
        azure_config.dce_uri,
        azure_config.dcr_immutable_id,
        azure_config.table_name
    )

    # Test connection
    if not bloodhound_manager.test_connection():
        logging.error(f"BloodHound API connection test failed for '{env_config.tenant_domain}'")
        return False

    logging.info(f"BloodHound API connection test passed for '{env_config.tenant_domain}'")

    # Get available domains
    res_domains = bloodhound_manager.get_available_domains()
    if not res_domains:
        logging.error("Failed to fetch available domains.")
        return False

    domains_data = res_domains.get("data", [])
    logging.info(f"Found {len(domains_data)} domains from BloodHound API.")

    # Filter domains
    filtered_domains = filter_domains(domains_data, env_config.selected_environments)
    if not filtered_domains:
        logging.info("No matching collected environments found.")
        return True

    # Get Azure Monitor token
    azure_monitor_token = bloodhound_manager.get_bearer_token()
    if not azure_monitor_token:
        logging.error("Failed to obtain Bearer token for Azure Monitor")
        return False

    # Collect tier zero assets
    assets = collect_tier_zero_assets(bloodhound_manager, filtered_domains)
    logging.info(f"Found {len(assets)} tier zero assets to process.")

    # Send assets to Azure Monitor
    if assets:
        successful_submissions, failed_submissions = send_tier_zero_assets_to_azure_monitor(
            assets,
            bloodhound_manager,
            azure_monitor_token,
            env_config.tenant_domain,
            filtered_domains
        )
        logging.info(f"Successful submissions: {successful_submissions}, Failed submissions: {failed_submissions}")
        return successful_submissions > 0 or len(assets) == 0

    return True


def run_tier_zero_assets_collection_process() -> bool:
    """
    Orchestrates the entire BloodHound Tier Zero Assets collection process.
    Returns True if successful, False otherwise.
    """
    logging.info("Starting BloodHound Tier Zero Assets collection process.")

    # Load configurations with tier zero assets table
    env_configs, azure_config = load_environment_configs("TIER_ZERO_ASSETS_TABLE_NAME")

    # Process each environment
    success = True
    for env_config in env_configs:
        logging.info(f"\n--- Starting Tier Zero Assets collection for environment '{env_config.tenant_domain}' ---")
        if not process_environment(env_config, azure_config):
            success = False

    logging.info("BloodHound Tier Zero Assets collection process completed for all environments")
    return success

