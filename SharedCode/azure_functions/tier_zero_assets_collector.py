import logging
import time
from azure.core.exceptions import ResourceNotFoundError
from ..utility.utils import (
    EnvironmentConfig,
    AzureConfig,
    load_environment_configs,
    fetch_env_variables,
    get_token_lists
)
from ..utility.bloodhound_manager import BloodhoundManager


def send_tier_zero_assets_to_azure_monitor(nodes_array, bloodhound_manager, azure_monitor_token, current_tenant_domain, filtered_domains_by_env):
    """
    Sends tier zero assets data to Azure Monitor and returns the count of successful and failed submissions.
    """
    successful_submissions = 0
    failed_submissions = 0

    if not nodes_array:
        logging.info("No Tier Zero Assets data to send to Azure Monitor for this environment.")
        return successful_submissions, failed_submissions

    for idx, data in enumerate(nodes_array, 1):
        logging.info(f"Sending Tier Zero Asset data {idx}/{len(nodes_array)}: ID {data.get('nodeId')} ({data.get('name')})")
        try:
            res = bloodhound_manager.send_tier_zero_assets_data(
                data,
                azure_monitor_token,
                filtered_domains_by_env,
            )
    
            print(f"Result of sending Tier Zero Asset data ID {data.get('nodeId')} is {res}")
            print(f"Processing Tier Zero Asset data {idx}/{len(nodes_array)}: {data.get('name')} in domain {data.get('domain_name')}")

            if res.get("status") == "success":
                successful_submissions += 1
            else:
                failed_submissions += 1
                logging.error(f"Failed to send Tier Zero Asset data ID {data.get('nodeId')}: {res.get('message', 'Unknown error')}")
        except Exception as e:
            failed_submissions += 1
            logging.error(f"Exception while sending Tier Zero Asset data ID {data.get('nodeId')}: {e}")
        time.sleep(0.1)

    logging.info(
        f"Tier Zero Asset processing for '{current_tenant_domain}' complete. Successful submissions: {successful_submissions}, Failed submissions: {failed_submissions}."
    )
    return successful_submissions, failed_submissions

def run_tier_zero_assets_collection_process() -> bool:
    """
    Orchestrates the entire BloodHound Tier Zero Assets collection and Azure Monitor submission process
    for multiple environments, handling each sequentially.
    Returns True if successful, False otherwise.
    """
    logging.info("Starting BloodHound Tier Zero Assets collection process.")

    try:
        # Fetch all required environment variables using utility
        env_vars = fetch_env_variables([
            "BLOODHOUND_TENANT_DOMAIN",
            "BLOODHOUND_TOKEN_ID_SECRET_NAME",
            "BLOODHOUND_TOKEN_KEY_SECRET_NAME",
            "MICROSOFT_ENTRA_ID_APPLICATION_TENANT_ID",
            "MICROSOFT_ENTRA_ID_APPLICATION_APP_ID",
            "MICROSOFT_ENTRA_ID_APPLICATION_APP_SECRET",
            "DCE_URI",
            "DCR_IMMUTABLE_ID",
            "TIER_ZERO_ASSETS_TABLE_NAME",
            "KEY_VAULT_URL",
        ])

        # Extract environment variables
        tenant_domains = env_vars["BLOODHOUND_TENANT_DOMAIN"]
        token_ids_secret_name = env_vars["BLOODHOUND_TOKEN_ID_SECRET_NAME"]
        token_keys_secret_name = env_vars["BLOODHOUND_TOKEN_KEY_SECRET_NAME"]
        tenant_id = env_vars["MICROSOFT_ENTRA_ID_APPLICATION_TENANT_ID"]
        app_id = env_vars["MICROSOFT_ENTRA_ID_APPLICATION_APP_ID"]
        app_secret = env_vars["MICROSOFT_ENTRA_ID_APPLICATION_APP_SECRET"]
        dce_uri = env_vars["DCE_URI"]
        dcr_immutable_id = env_vars["DCR_IMMUTABLE_ID"]
        table_name = env_vars["TIER_ZERO_ASSETS_TABLE_NAME"]
        key_vault_url = env_vars["KEY_VAULT_URL"]

        logging.info(f"Configuration loaded for Tier Zero Assets. Key Vault URL: {key_vault_url}")

        # Split comma-separated values into lists
        list_tenant_domains = [td.strip() for td in tenant_domains.split(',')]

        # Handle token IDs and keys
        # if token_id is not None and token_key is not None:
        #     all_token_ids = [tid.strip() for tid in token_id.split(',')]
        #     all_token_keys = [tkey.strip() for tkey in token_key.split(',')]
        # else:
        #     all_token_ids, all_token_keys = get_token_lists(
        #         key_vault_url=key_vault_url,
        #         token_ids_secret_name=token_ids_secret_name,
        #         token_keys_secret_name=token_keys_secret_name
        #     )

        all_token_ids, all_token_keys = get_token_lists(
                key_vault_url=key_vault_url,
                token_ids_secret_name=token_ids_secret_name,
                token_keys_secret_name=token_keys_secret_name
            )

        if not (len(list_tenant_domains) == len(all_token_ids) == len(all_token_keys)):
            logging.error("Environment variable lists for domains, token IDs, and token keys have a mismatch in length. Exiting.")
            return

        num_environments = len(list_tenant_domains)
        logging.info(f"Identified {num_environments} BloodHound environments to process.")

        # Loop through each environment
        for i in range(num_environments):
            current_tenant_domain = list_tenant_domains[i]
            current_token_id = all_token_ids[i]
            current_token_key = all_token_keys[i]

            logging.info(f"\n--- Starting Tier Zero Assets collection for environment '{current_tenant_domain}' ---")

            # 3. Initialize BloodhoundManager for the current environment
            bloodhound_manager = BloodhoundManager(
                current_tenant_domain, current_token_id, current_token_key, logger=logging
            )
            bloodhound_manager.set_azure_monitor_config(
                tenant_id, app_id, app_secret, dce_uri, dcr_immutable_id, table_name
            )

            # 4. Test BloodHound API connection
            connection_response = bloodhound_manager.test_connection()
            if not connection_response:
                logging.error(f"BloodHound API connection test failed for Tier Zero Assets at '{current_tenant_domain}'. Aborting all further collection.")
                return # Exit the entire script if a single connection fails

            logging.info(f"BloodHound API connection test passed for Tier Zero Assets at '{current_tenant_domain}'. Starting collection...")

            # 5. Get available domains from BloodHound and apply environment filter
            res_domains = bloodhound_manager.get_available_domains()
            if not res_domains:
                logging.error("Failed to fetch available domains. Cannot proceed with Tier Zero Assets collection for this environment.")
                continue # Skip to the next environment if domain fetch fails

            all_domains_data = res_domains.get("data", [])
            logging.info(f"Found {len(all_domains_data)} domains from BloodHound API.")

            filtered_domains_by_env = [
                domain for domain in all_domains_data if domain.get("collected") is True
            ]

            if not filtered_domains_by_env:
                logging.info("No collected or selected environments found to query Tier Zero Assets for this environment. Skipping.")
                continue

            logging.info(f"Filtered {len(filtered_domains_by_env)} domains for Tier Zero Assets collection.")

            # 6. Fetch Tier Zero Assets using Cypher query
            cypher_response = bloodhound_manager.fetch_tier_zero_assets()

            if (
                not cypher_response
                or "data" not in cypher_response
                or "nodes" not in cypher_response["data"]
            ):
                logging.error("Failed to fetch Tier Zero assets or received unexpected response structure for this environment. Skipping.")
                continue

            nodes_array = []
            for node_id, node_data in cypher_response["data"]["nodes"].items():
                # Exclude 'Meta' kind nodes as per original script's filtering
                if node_data.get("kind") == "Meta":
                    continue

                properties = node_data.get("properties", {})
                name = bloodhound_manager.extract_name(node_data, properties, node_id)
                domain_name = bloodhound_manager.extract_domain_name(
                    node_data, properties, name, filtered_domains_by_env
                )

                # Create a combined dictionary including 'nodeId', 'domain_name', 'name', and all other node_data
                combined_node_data = {
                    "nodeId": node_id,
                    "domain_name": domain_name,
                    "name": name,
                    **node_data,
                }
                nodes_array.append(combined_node_data)

            logging.info(f"Found {len(nodes_array)} Tier Zero Assets to process for this environment.")

            # 7. Get Bearer Token for Azure Monitor
            azure_monitor_token = bloodhound_manager.get_bearer_token()
            if not azure_monitor_token:
                logging.error("Failed to obtain Bearer token for Azure Monitor. Aborting data submission for this environment.")
                continue

            logging.info("Bearer token obtained successfully for Azure Monitor.")

            # 8. Send Tier Zero Assets data to Azure Monitor
            successful_submissions, failed_submissions = send_tier_zero_assets_to_azure_monitor(
                nodes_array,
                bloodhound_manager,
                azure_monitor_token,
                current_tenant_domain,
                filtered_domains_by_env
            )

            logging.info(f"Successful submissions: {successful_submissions} & Failed submissions: {failed_submissions}")

        logging.info("BloodHound Tier Zero Assets collection process completed for all environments.")

    except KeyError as e:
        logging.error(f"Missing one or more required environment variables: {e}. Exiting process.")
    except ResourceNotFoundError as e:
        logging.error(f"Resource not found in Azure Key Vault: {e}. Exiting process.")
    except Exception as ex:
        logging.error(f"Unexpected error occurred: {ex}")
