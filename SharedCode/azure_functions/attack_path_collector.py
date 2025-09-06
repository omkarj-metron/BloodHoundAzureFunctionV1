import logging
import time
import datetime
from ..utility.utils import fetch_env_variables, get_token_lists

from ..utility.bloodhound_manager import BloodhoundManager

def send_attack_paths_to_azure_monitor(all_collected_attack_paths, bloodhound_manager, azure_monitor_token, unique_finding_types_data, current_tenant_domain, all_domains_data):
    """
    Sends attack path details to Azure Monitor and returns the count of successful and failed submissions.
    """
    successful_submissions = 0
    failed_submissions = 0
    if all_collected_attack_paths:
        logging.info(f"Sending {len(all_collected_attack_paths)} collected attack path details to Azure Monitor.")
        for i, data_item in enumerate(all_collected_attack_paths, 1):
            try:
                result = bloodhound_manager.send_attack_data(
                    data_item, azure_monitor_token, unique_finding_types_data, current_tenant_domain, all_domains_data
                )
                print(f"Processing attack path log entry {i}/{len(all_collected_attack_paths)}: {data_item.get('id')}")
                logging.info(f"Result of sending attack path log for '{data_item.get('id')}' is {result}")
                if result.get("status") == "success":
                    successful_submissions += 1
                else:
                    failed_submissions += 1
                    logging.error(f"Failed to send attack path log for ID '{data_item.get('id')}': {result.get('message', 'Unknown error')}")
            except Exception as e:
                failed_submissions += 1
                logging.error(f"Exception while sending attack path log for ID '{data_item.get('id')}': {e}")
            time.sleep(0.1)
    else:
        logging.info("No attack path details data was collected to send to Azure Monitor for this environment.")
    logging.info(f"Attack paths processing complete for '{current_tenant_domain}'. Successful submissions: {successful_submissions}, Failed submissions: {failed_submissions}.")
    return successful_submissions, failed_submissions

def run_attack_paths_collection_process(last_attack_path_timestamps = None):
    """
    Orchestrates the entire BloodHound attack paths collection and Azure Monitor submission process
    for multiple environments, handling each sequentially.
    """
    logging.info("Starting BloodHound attack paths collection process.")
    last_attack_path_timestamps = last_attack_path_timestamps or {}
    DEFAULT_LOOKBACK_DAYS = 1
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
            "ATTACK_PATHS_TABLE_NAME",
            "KEY_VAULT_URL",
            "SELECTED_BLOODHOUND_ENVIRONMENTS",
            "SELECTED_FINDING_TYPES",
            "BLOODHOUND_TOKEN_ID",
            "BLOODHOUND_TOKEN_KEY"
        ])

        tenant_domains = env_vars["BLOODHOUND_TENANT_DOMAIN"]
        token_ids_secret_name = env_vars["BLOODHOUND_TOKEN_ID_SECRET_NAME"]
        token_keys_secret_name = env_vars["BLOODHOUND_TOKEN_KEY_SECRET_NAME"]
        tenant_id = env_vars["MICROSOFT_ENTRA_ID_APPLICATION_TENANT_ID"]
        app_id = env_vars["MICROSOFT_ENTRA_ID_APPLICATION_APP_ID"]
        app_secret = env_vars["MICROSOFT_ENTRA_ID_APPLICATION_APP_SECRET"]
        dce_uri = env_vars["DCE_URI"]
        dcr_immutable_id = env_vars["DCR_IMMUTABLE_ID"]
        table_name = env_vars["ATTACK_PATHS_TABLE_NAME"]
        key_vault_url = env_vars["KEY_VAULT_URL"]
        selected_bhe_environments = env_vars["SELECTED_BLOODHOUND_ENVIRONMENTS"]
        selected_finding_types = env_vars["SELECTED_FINDING_TYPES"]
        token_id = env_vars["BLOODHOUND_TOKEN_ID"]
        token_key = env_vars["BLOODHOUND_TOKEN_KEY"]

        logging.info(f"Config loaded for attack paths. Key Vault URL: {key_vault_url}")

        # Split comma-separated values into lists
        list_tenant_domains = [td.strip() for td in tenant_domains.split(',')]
        # If token_id and token_key are present, use them directly; otherwise, fetch from Key Vault
        if token_id is not None and token_key is not None:
            all_token_ids = [tid.strip() for tid in token_id.split(',')]
            all_token_keys = [tkey.strip() for tkey in token_key.split(',')]
        else:
            all_token_ids, all_token_keys = get_token_lists(
                key_vault_url=key_vault_url,
                token_ids_secret_name=token_ids_secret_name,
                token_keys_secret_name=token_keys_secret_name
            )

        # Check if all lists have the same length
        if not (len(list_tenant_domains) == len(all_token_ids) == len(all_token_keys)):
            logging.error("Mismatch in the number of environments. The lengths of BLOODHOUND_TENANT_DOMAIN, BLOODHOUND_TOKEN_ID_SECRET_NAME, and BLOODHOUND_TOKEN_KEY_SECRET_NAME must be equal. Exiting.")
            return

        num_environments = len(list_tenant_domains)
        logging.info(f"Identified {num_environments} BloodHound environments to process.")
        print(f"Identified {num_environments} BloodHound environments to process.")

        # Loop through each environment
        for i in range(num_environments):
            try: 
                current_tenant_domain = list_tenant_domains[i]
                current_token_id = all_token_ids[i]
                current_token_key = all_token_keys[i]

                print(f"Processing BloodHound Environment #{i+1}: {current_tenant_domain}")
                
                logging.info(f"\n--- Starting process for BloodHound Environment #{i+1} at '{current_tenant_domain}' ---")

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
                    print(f"Connection test to BloodHound API failed for '{current_tenant_domain}'. Aborting further collection for this environment.")
                    logging.error(f"BloodHound API connection test failed for '{current_tenant_domain}'. Aborting all further collection.")
                    return # Exit the entire script if a single connection fails

                logging.info(f"BloodHound API connection test passed for '{current_tenant_domain}'. Starting collection...")

                # 5. Get available domains from BloodHound and apply environment filter
                res_domains = bloodhound_manager.get_available_domains()
                if not isinstance(res_domains, dict):
                    logging.error(f"Expected dict for available domains, got {type(res_domains)}: {res_domains}")
                    all_domains_data = []
                else:
                    all_domains_data = res_domains.get("data", [])
                if not res_domains:
                    logging.error("Failed to fetch available domains. Cannot proceed.")
                    continue # Skip to the next environment if domain fetch fails

                all_domains_data = res_domains.get("data", [])
                logging.info(f"Found {len(all_domains_data)} domains from BloodHound API.")

                # Apply Selected_BloodHound_Environment filter
                filtered_domains_by_env = []
                if selected_bhe_environments.strip().lower() == "all":
                    filtered_domains_by_env = [
                        domain for domain in all_domains_data if domain.get("collected") is True
                    ]
                else:
                    domain_names_to_include = [
                        name.strip() for name in selected_bhe_environments.split(",")
                    ]
                    filtered_domains_by_env = [
                        domain
                        for domain in all_domains_data
                        if domain.get("collected") is True
                        and domain.get("name").strip() in domain_names_to_include
                    ]

                if not filtered_domains_by_env:
                    logging.info("No collected or selected environments found to query attack paths. Skipping.")
                    continue

                logging.info(f"Filtered {len(filtered_domains_by_env)} domains for attack path collection.")

                # 6. Fetch available finding types for each filtered domain and apply filter
                final_domains_to_process = []
                selected_finding_types_list = (
                    [t.strip() for t in selected_finding_types.split(",")]
                    if selected_finding_types.strip().lower() != "all"
                    else []
                )

                for domain in filtered_domains_by_env:
                    domain_id = domain.get("id")
                    domain_name = domain.get("name")
                    available_types = bloodhound_manager.get_available_types_for_domain(domain_id)

                    if not isinstance(available_types, list):
                        logging.error(f"Expected list for available types, got {type(available_types)}: {available_types}")
                        available_types = []

                    
                    if selected_finding_types_list:
                        filtered_domain_types = [
                            _type for _type in available_types if _type in selected_finding_types_list
                        ]
                    else:
                        filtered_domain_types = available_types
                    
                    if filtered_domain_types:
                        domain["available_types"] = filtered_domain_types
                        final_domains_to_process.append(domain)
                        logging.info(f"Domain '{domain_name}' has {len(filtered_domain_types)} relevant finding types.")
                    else:
                        logging.info(f"Domain '{domain_name}' has no relevant finding types after filtering. Skipping.")

                if not final_domains_to_process:
                    logging.info("No domains or finding types remain after filtering. Skipping this environment.")
                    continue

                # 7. Get unique finding types text details
                unique_finding_types_data = bloodhound_manager.get_all_path_asset_details_for_finding_types(final_domains_to_process)
                logging.info(f"Fetched asset text details for {len(unique_finding_types_data)} unique finding types/details combinations.")

                # 8. Get Bearer Token for Azure Monitor
                azure_monitor_token = bloodhound_manager.get_bearer_token()
                if not azure_monitor_token:
                    logging.error("Failed to obtain Bearer token for Azure Monitor. Aborting submission for this environment.")
                    continue

                # 9. Fetch and send attack path details
                all_collected_attack_paths = []
                domain_latest_timestamps = {}
                for domain_entry in final_domains_to_process:
                    domain_id = domain_entry.get("id")
                    domain_name = domain_entry.get("name")
                    available_types_for_domain = domain_entry.get("available_types", [])
                    
                    if not available_types_for_domain:
                        logging.info(f"[SKIPPED] No available types to fetch for domain {domain_name}.")
                        continue
                    
                    for attack_type in available_types_for_domain:
                        logging.info(f"Fetching attack path details for domain: {domain_name}, type: {attack_type}")
                        attack_details_for_type = bloodhound_manager.get_attack_path_details(domain_id, attack_type)
                        if not isinstance(attack_details_for_type, list):
                            logging.warning(f"Skipping attack path details for domain {domain_name}, type {attack_type}: expected list, got {type(attack_details_for_type)}")
                            continue
                        if attack_details_for_type:
                            attack_details_for_type = [x for x in attack_details_for_type if isinstance(x, dict)]
                            all_collected_attack_paths.extend(attack_details_for_type)
                            logging.info(f"Fetched {len(attack_details_for_type)} attack path details for {attack_type} in {domain_name}.")
                        else:
                            logging.warning(f"No attack path details found for {attack_type} in domain {domain_name}.")

                if all_collected_attack_paths:
                    filtered_attack_paths = []
                    for i, data_item in enumerate(all_collected_attack_paths, 1):
                        if not isinstance(data_item, dict):
                            logging.error(f"Skipping non-dict attack path entry at index {i}: {data_item}")
                            continue
                        item_updated_at  = data_item.get("updated_at")
                        domain_name = data_item.get("Environment")
                        logging.info(f"For domain {domain_name} item_updated_at: {item_updated_at}")
                        last_saved_ts = last_attack_path_timestamps.get(current_tenant_domain, {}).get(domain_name, "")
                        if not last_saved_ts:
                            logging.info(f"No last saved timestamp found for {domain_name}. Using current timestamp.")
                            last_saved_ts = (datetime.datetime.utcnow() - datetime.timedelta(days=DEFAULT_LOOKBACK_DAYS)).isoformat() + "Z"
                        else:
                            logging.info(f"Last saved timestamp for {domain_name}: {last_saved_ts}")
                        if not last_saved_ts or item_updated_at > last_saved_ts:
                            filtered_attack_paths.append(data_item)
                            if domain_name not in domain_latest_timestamps:
                                domain_latest_timestamps[domain_name] = item_updated_at
                            else:
                                domain_latest_timestamps[domain_name] = max(
                                    domain_latest_timestamps[domain_name], item_updated_at
                                )
                    all_collected_attack_paths = filtered_attack_paths


                # Move the attack path sending logic to a separate function for modularity
                successful_submissions, failed_submissions = send_attack_paths_to_azure_monitor(
                    all_collected_attack_paths, bloodhound_manager, azure_monitor_token, unique_finding_types_data, current_tenant_domain, all_domains_data
                )

                if current_tenant_domain not in last_attack_path_timestamps:
                    last_attack_path_timestamps[current_tenant_domain] = {}
                for domain_name, latest_ts in domain_latest_timestamps.items():
                    last_attack_path_timestamps[current_tenant_domain][domain_name] = latest_ts
                    logging.info(f"Updated last attack path timestamp for {current_tenant_domain} - {domain_name}: {latest_ts}")
                logging.info(f"Attack paths processing complete for '{current_tenant_domain}'. Successful submissions: {successful_submissions}, Failed submissions: {failed_submissions}.")
            except Exception as e:
                logging.error(f"Exception while processing attack paths for environment '{current_tenant_domain}': {e}")
                continue
        logging.info("BloodHound attack paths collection process finished.")
        logging.info(f"Final last_attack_path_timestamps: {last_attack_path_timestamps}")
        return last_attack_path_timestamps
    except KeyError as e:
        logging.error(f"Missing one or more required environment variables: {e}. Exiting process.")
        return
    except Exception as ex:
        logging.error(f"Unexpected Error occurred. {ex}")
        return