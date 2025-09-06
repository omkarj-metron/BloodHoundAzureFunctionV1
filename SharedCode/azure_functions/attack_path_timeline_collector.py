import logging
import time
import json
import datetime
from ..utility.utils import fetch_env_variables, get_token_lists

from ..utility.bloodhound_manager import BloodhoundManager


def send_timeline_data_to_azure_monitor(all_collected_timelines, bloodhound_manager, azure_monitor_token, unique_finding_types_data, current_tenant_domain, all_domains_data):
    """
    Sends attack timeline details to Azure Monitor and returns the count of successful and failed submissions.
    """
    successful_submissions = 0
    failed_submissions = 0
    if all_collected_timelines:
        logging.info(f"Sending {len(all_collected_timelines)} collected attack timeline details to Azure Monitor.")
        for i, data_item in enumerate(all_collected_timelines, 1):
            try:
                result = bloodhound_manager.send_attack_timeline_data(
                    data_item, azure_monitor_token, unique_finding_types_data, current_tenant_domain, all_domains_data
                )
                print(f"Processing attack timeline log entry {i}/{len(all_collected_timelines)}: {data_item.get('id')}")
                logging.info(f"Result of sending attack timeline log for '{data_item.get('id')}' is {result}")
                if result.get("status") == "success":
                    successful_submissions += 1
                else:
                    failed_submissions += 1
                    logging.error(f"Failed to send attack timeline log for ID '{data_item.get('id')}': {result.get('message', 'Unknown error')}")
            except Exception as e:
                failed_submissions += 1
                logging.error(f"Exception while sending attack timeline log for ID '{data_item.get('id')}': {e}")
            time.sleep(0.1)
    else:
        logging.info("No attack timeline details data was collected to send to Azure Monitor for this environment.")
    logging.info(f"Attack timeline processing complete for '{current_tenant_domain}'. Successful submissions: {successful_submissions}, Failed submissions: {failed_submissions}.")
    return successful_submissions, failed_submissions


def run_attack_paths_timeline_collection_process(
    last_attack_path_timeline_timestamps=None
):
    """
    Orchestrates the entire BloodHound attack paths timeline collection and Azure Monitor submission process
    for multiple environments, handling each sequentially.
    """
    logging.info("Starting BloodHound attack paths timeline collection process.")
    last_attack_path_timeline_timestamps = last_attack_path_timeline_timestamps or {}

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
            "ATTACK_PATHS_TIMELINE_TABLE_NAME",
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
        table_name = env_vars["ATTACK_PATHS_TIMELINE_TABLE_NAME"]
        key_vault_url = env_vars["KEY_VAULT_URL"]
        selected_bhe_environments = env_vars["SELECTED_BLOODHOUND_ENVIRONMENTS"]
        selected_finding_types = env_vars["SELECTED_FINDING_TYPES"]
        token_id = env_vars["BLOODHOUND_TOKEN_ID"]
        token_key = env_vars["BLOODHOUND_TOKEN_KEY"]

        logging.info(f"Config loaded for attack timeline. Key Vault URL: {key_vault_url}")

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
        if not (len(list_tenant_domains) == len(all_token_ids) == len(all_token_keys)):
            logging.error("Mismatch in the number of environments. The lengths of BLOODHOUND_TENANT_DOMAIN, BLOODHOUND_TOKEN_ID, and BLOODHOUND_TOKEN_KEY must be equal. Exiting.")
            return
        
        print(f"All lists are: {list_tenant_domains}, {all_token_ids}, {all_token_keys}")

        num_environments = len(list_tenant_domains)
        logging.info(f"Identified {num_environments} BloodHound environments to process.")

        # Loop through each environment
        for i in range(num_environments):
            current_tenant_domain = list_tenant_domains[i]
            current_token_id = all_token_ids[i]
            current_token_key = all_token_keys[i]

            print(f"Current environment: {current_tenant_domain}")
            
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
                logging.error(f"BloodHound API connection test failed for '{current_tenant_domain}'. Aborting all further collection.")
                return # Exit the entire script if a single connection fails

            logging.info(f"BloodHound API connection test passed for '{current_tenant_domain}'. Starting collection...")

            # 5. Get available domains from BloodHound and apply environment filter
            res_domains = bloodhound_manager.get_available_domains()
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

            logging.info(f"Filtered {len(filtered_domains_by_env)} domains for attack path collection based on environments.")

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
                
                if selected_finding_types_list:
                    filtered_domain_types = [
                        _type for _type in available_types if _type in selected_finding_types_list
                    ]
                else:
                    filtered_domain_types = available_types
                
                if filtered_domain_types:
                    domain["available_types"] = filtered_domain_types
                    final_domains_to_process.append(domain)
                    logging.info(f"Domain '{domain_name}' has {len(filtered_domain_types)} relevant finding types after filtering.")
                else:
                    logging.info(f"Domain '{domain_name}' has no relevant finding types after filtering. Skipping.")

            if not final_domains_to_process:
                logging.info("No domains or finding types remain after filtering. Skipping this environment.")
                continue

            # 7. Get unique finding types text details
            unique_finding_types_data = bloodhound_manager.get_all_path_asset_details_for_finding_types(final_domains_to_process)
            logging.info(f"Fetched asset text details for {len(unique_finding_types_data)} unique finding types/details combinations.")

            consolidated_attack_paths_timeline = []

            for domain in final_domains_to_process:
                domain_id = domain.get("id")
                domain_name = domain.get("name")
                available_types = domain.get("available_types", [])

                if not available_types:
                    logging.warning(f"No available types for domain {domain_name} after filtering. Skipping.")
                    continue

                domain_attack_path_entries = []

                for attack_type in available_types:
                    logging.info(f"Fetching attack path timeline for {domain_name} [{attack_type}]...")
                    last_attack_path_timeline_timestamps_for_env = last_attack_path_timeline_timestamps.get(current_tenant_domain, {}).get(domain_name, "")
                    logging.info(f"Last attack path timeline timestamp for {domain_name} is {last_attack_path_timeline_timestamps_for_env}")
                    attack_path_timeline = bloodhound_manager.get_attack_path_sparkline_timeline(
                        domain_id, attack_type, start_from=last_attack_path_timeline_timestamps_for_env
                    )

                    if attack_path_timeline:
                        domain_attack_path_entries.extend(attack_path_timeline)
                        logging.info(f"Fetched {len(attack_path_timeline)} entries for {attack_type} in domain {domain_name}.")
                    else:
                        logging.warning(f"No data returned for {attack_type} in domain {domain_name}.")

                # Update latest timestamp **once per domain**, after collecting all attack types
                if domain_attack_path_entries:
                    latest_timestamp = max(
                        [ap.get("updated_at", "") for ap in domain_attack_path_entries if ap.get("updated_at")],
                        default=None
                    )
                    if latest_timestamp:
                        # ensure nested dict exists
                        if current_tenant_domain not in last_attack_path_timeline_timestamps:
                            last_attack_path_timeline_timestamps[current_tenant_domain] = {}
                        last_attack_path_timeline_timestamps[current_tenant_domain][domain_name] = latest_timestamp
                        logging.info(f"Updated last_attack_path_timeline_timestamps for {current_tenant_domain}/{domain_name} to {latest_timestamp}")

                # Add domain_attack_path_entries to the consolidated list
                consolidated_attack_paths_timeline.extend(domain_attack_path_entries)


            logging.info(f"Total consolidated attack path timeline entries for this environment: {len(consolidated_attack_paths_timeline)}")

            # 8. Get Bearer Token for Azure Monitor
            token = bloodhound_manager.get_bearer_token()
            if not token:
                logging.error("Failed to obtain Bearer token for Azure Monitor. Aborting data submission for this environment.")
                continue

            logging.info("Bearer token obtained successfully for Azure Monitor.")

            # 9. Fetch and send posture stats (attack path timeline data)
            submission_results = []
            if not consolidated_attack_paths_timeline:
                logging.info("No attack path timeline data to send to Azure Monitor. Exiting.")
                continue

            for i, attack in enumerate(consolidated_attack_paths_timeline, 1):
                logging.info(f"Sending attack data {i}/{len(consolidated_attack_paths_timeline)}: ID {attack.get('id')}")
                try:
                    res = bloodhound_manager.send_attack_path_timeline_data(
                        attack, token, unique_finding_types_data, final_domains_to_process
                    )
                    
                    print(f"Result of sending attack data ID {attack.get('id')} is {res}")

                    submission_results.append({"id": attack.get("id"), "status": "success", "response": res})
                    logging.info(f"Result of sending attack data ID {attack.get('id')} is {res}")
                except Exception as e:
                    logging.error(f"Error sending attack data ID {attack.get('id')}: {e}")
                    submission_results.append({"id": attack.get("id"), "status": "error", "message": str(e)})
                time.sleep(0.1)

            logging.info(f"All attack path timeline data submission results for '{current_tenant_domain}': {json.dumps(submission_results, indent=2)}")

        logging.info("BloodHound attack paths timeline collection process completed.")
        logging.info(f"Final last_attack_path_timeline_timestamps state: {last_attack_path_timeline_timestamps}")
        return last_attack_path_timeline_timestamps
    except KeyError as e:
        logging.error(f"Missing one or more required environment variables: {e}. Exiting process.")
        return
    except Exception as ex:
        logging.error(f"Unexpected Error occurred. {ex}")
        return