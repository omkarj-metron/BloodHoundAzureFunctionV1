import logging
import time
from ..utility.utils import fetch_env_variables, get_token_lists

from ..utility.bloodhound_manager import BloodhoundManager


def send_posture_history_to_azure_monitor(posture_history_data, bloodhound_manager, azure_monitor_token, current_tenant_domain, domains_data):
    """
    Sends posture history data to Azure Monitor and returns the count of successful and failed submissions.
    """
    successful_submissions = 0
    failed_submissions = 0
    if posture_history_data:
        logging.info(f"Sending {len(posture_history_data)} posture history records to Azure Monitor.")
        print(f"All posture history are: {posture_history_data}")
        for i, data_item in enumerate(posture_history_data, 1):
            try:
                result = bloodhound_manager.send_posture_history_logs(
                    data_item, azure_monitor_token, current_tenant_domain, domains_data
                )

                # result = bloodhound_manager.send_posture_history_logs(data_item, azure_monitor_token, current_tenant_domain, domains_data)
                print(f"Processing posture history entry {i}/{len(posture_history_data)}: {data_item}")
                logging.info(f"Result of sending posture history is {result}")
                if result.get("status") == "success":
                    successful_submissions += 1
                else:
                    failed_submissions += 1
                    logging.error(f"Failed to send posture history for date '{data_item.get('value')}': {result.get('message', 'Unknown error')}")
            except Exception as e:
                failed_submissions += 1
                logging.error(f"Exception while sending posture history for date '{data_item.get('value')}': {e}")
            time.sleep(0.1)
    else:
        logging.info("No posture history data was collected to send to Azure Monitor for this environment.")
    logging.info(f"Posture history processing complete for '{current_tenant_domain}'. Successful submissions: {successful_submissions}, Failed submissions: {failed_submissions}.")
    return successful_submissions, failed_submissions


def run_posture_history_collection_process(last_posture_history_timestamps=None):
    """
    Orchestrates the entire BloodHound posture history collection and Azure Monitor submission process
    for multiple environments, handling each sequentially.
    """
    logging.info("Starting BloodHound posture history collection process.")
    last_posture_history_timestamps = last_posture_history_timestamps or {}

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
            "POSTURE_HISTORY_TABLE_NAME",
            "KEY_VAULT_URL",
            "BLOODHOUND_TOKEN_ID",
            "BLOODHOUND_TOKEN_KEY",
            "SELECTED_BLOODHOUND_ENVIRONMENTS"
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
        table_name = env_vars["POSTURE_HISTORY_TABLE_NAME"]
        key_vault_url = env_vars["KEY_VAULT_URL"]
        token_id = env_vars["BLOODHOUND_TOKEN_ID"]
        token_key = env_vars["BLOODHOUND_TOKEN_KEY"]

        logging.info(f"Config loaded for posture history. Key Vault URL: {key_vault_url}")

        # Split comma-separated values into lists
        list_tenant_domains = [td.strip() for td in tenant_domains.split(',')]

        # Handle token IDs and keys
        if token_id is not None and token_key is not None:
            all_token_ids = [tid.strip() for tid in token_id.split(',')]
            all_token_keys = [tkey.strip() for tkey in token_key.split(',')]
        else:
            all_token_ids, all_token_keys = get_token_lists(
                key_vault_url=key_vault_url,
                token_ids_secret_name=token_ids_secret_name,
                token_keys_secret_name=token_keys_secret_name
            )

        # Validate environment configurations
        if not (len(list_tenant_domains) == len(all_token_ids) == len(all_token_keys)):
            logging.error("Mismatch in the number of environments. The lengths of BLOODHOUND_TENANT_DOMAIN, BLOODHOUND_TOKEN_ID, and BLOODHOUND_TOKEN_KEY must be equal. Exiting.")
            return None

        num_environments = len(list_tenant_domains)
        logging.info(f"Identified {num_environments} BloodHound environments to process.")

        selected_bhe_environments = env_vars["SELECTED_BLOODHOUND_ENVIRONMENTS"]

        # Process each environment
        for i in range(num_environments):
            current_tenant_domain = list_tenant_domains[i]
            current_token_id = all_token_ids[i]
            current_token_key = all_token_keys[i]

            logging.info(f"\n--- Starting posture history collection for environment '{current_tenant_domain}' ---")

            # Initialize BloodhoundManager
            bloodhound_manager = BloodhoundManager(
                current_tenant_domain, current_token_id, current_token_key, logger=logging
            )
            bloodhound_manager.set_azure_monitor_config(
                tenant_id, app_id, app_secret, dce_uri, dcr_immutable_id, table_name
            )

            # Test BloodHound API connection
            connection_response = bloodhound_manager.test_connection()
            if not connection_response:
                logging.error(
                    f"BloodHound API connection test failed for '{current_tenant_domain}'. Skipping this environment."
                )
                continue

            # Get available domains
            res_domains = bloodhound_manager.get_available_domains()
            if not res_domains:
                logging.error("Failed to fetch available domains. Skipping this environment.")
                continue

            domains_data = res_domains.get("data", [])
            logging.info(f"Found {len(domains_data)} domains from BloodHound API.")

            # Apply Selected_BloodHound_Environment filter
            if selected_bhe_environments.strip().lower() == "all":
                filtered_domains_by_env = [
                    domain for domain in domains_data if domain.get("collected") is True
                ]
            else:
                domain_names_to_include = [
                    name.strip() for name in selected_bhe_environments.split(",")
                ]
                filtered_domains_by_env = [
                    domain
                    for domain in domains_data
                    if domain.get("collected") is True
                    and domain.get("name").strip() in domain_names_to_include
                ]

            if not filtered_domains_by_env:
                logging.info("No collected or selected environments found. Skipping.")
                continue

            environment_ids = [
                domain["id"] for domain in filtered_domains_by_env if domain.get("id")
            ]
            if not environment_ids:
                logging.info("No environment IDs found. Skipping this environment.")
                continue

            # Get Azure Monitor Bearer Token
            azure_monitor_token = bloodhound_manager.get_bearer_token()
            if not azure_monitor_token:
                logging.error(
                    "Failed to obtain Bearer token for Azure Monitor. Skipping this environment."
                )
                continue

            # Fetch and send posture history
            data_types_to_fetch = ["findings", "exposure", "assets", "attack-paths"]
            all_collected_data = []

            for env_id in environment_ids:
                for data_type in data_types_to_fetch:
                    last_posture_history_timestamps_for_env = (
                        last_posture_history_timestamps
                        .get(current_tenant_domain, {})
                        .get(env_id, {})
                        .get(data_type, "")
                    )

                    posture_history_response = bloodhound_manager.get_posture_history(
                        data_type, environment_id=env_id, start=last_posture_history_timestamps_for_env
                    )

                    if (
                        posture_history_response
                        and "data" in posture_history_response
                        and posture_history_response["data"]
                    ):
                        response_data = posture_history_response["data"]

                        for data_item in response_data:
                            data_item["start_date"] = posture_history_response.get("start", "")
                            data_item["end_date"] = posture_history_response.get("end", "")
                            data_item["domain_id"] = env_id
                            data_item["type"] = data_type
                            data_item["tenant_domain"] = current_tenant_domain
                            all_collected_data.append(data_item)

                        # Update timestamps
                        latest_timestamp = max(
                            item.get("date", "") for item in response_data
                        )
                        last_posture_history_timestamps.setdefault(
                            current_tenant_domain, {}
                        ).setdefault(env_id, {})[data_type] = latest_timestamp

            # Send collected data
            if all_collected_data:
                send_posture_history_to_azure_monitor(
                    all_collected_data[:200],
                    bloodhound_manager,
                    azure_monitor_token,
                    current_tenant_domain,
                    domains_data
                )


        # End of processing all environments
        logging.info("BloodHound posture history collection process finished for all environments.")
        logging.info(f"Final last_posture_history_timestamps: {last_posture_history_timestamps}")
        return last_posture_history_timestamps

    except KeyError as e:
        logging.error(f"Missing one or more required environment variables: {e}. Exiting process.")
        return None
    except Exception as ex:
        logging.error(f"Unexpected Error occurred: {ex}")
        return None
