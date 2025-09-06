import logging
import time
from ..utility.utils import fetch_env_variables, get_token_lists

from ..utility.bloodhound_manager import BloodhoundManager

def bloodhound_audit_logs_collector_main_function(
    last_audit_logs_timestamp=None
):
    """
    Azure Function Timer Trigger to collect BloodHound audit logs and send them to Azure Monitor.
    This version processes multiple BloodHound environments.
    """
    logging.info("Python timer trigger function 'bloodhound_audit_logs_collector' executed.")
    last_audit_logs_timestamp = last_audit_logs_timestamp or {}
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
            "AUDIT_LOGS_TABLE_NAME",
            "KEY_VAULT_URL",
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
        table_name = env_vars["AUDIT_LOGS_TABLE_NAME"]
        key_vault_url = env_vars["KEY_VAULT_URL"]
        token_id = env_vars["BLOODHOUND_TOKEN_ID"]
        token_key = env_vars["BLOODHOUND_TOKEN_KEY"]

        logging.info(f"Config loaded. Key Vault URL: {key_vault_url}")

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
            logging.error("Environment variable lists for domains, token IDs, and token keys have a mismatch in length. Exiting.")
            return
        print(f"All lists: {list_tenant_domains}, {all_token_ids}, {all_token_keys}")

        num_environments = len(list_tenant_domains)
        logging.info(f"Identified {num_environments} BloodHound environments to process.")

        # Process each BloodHound environment sequentially
        for i in range(num_environments):
            current_tenant_domain = list_tenant_domains[i]
            current_token_id = all_token_ids[i]
            current_token_key = all_token_keys[i]

            # last_timestamp = last_processed_timestamps.get(current_tenant_domain, "")
            # logging.info(f"Last timestamp for '{current_tenant_domain}': {last_timestamp if last_timestamp else 'None'}")
            # print(f"Last timestamp for '{current_tenant_domain}': {last_timestamp if last_timestamp else 'None'}")

            logging.info(f"\n--- Starting audit log collection for environment '{current_tenant_domain}' ---")

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
                logging.error(f"BloodHound API connection test failed for '{current_tenant_domain}'. Aborting log collection for all environments.")
                return

            logging.info(f"BloodHound API connection test passed for '{current_tenant_domain}'. Starting log collection...")

            # 5. Fetch Audit Logs from BloodHound
            print(f"Last audit logs timestamp before fetching: {last_audit_logs_timestamp}")
            audit_logs = bloodhound_manager.get_audit_logs(last_audit_logs_timestamp.get(current_tenant_domain, ""))
            # print(f"Audit logs: {audit_logs}")
            if not audit_logs:
                logging.warning("No new audit logs found to process for this environment. Skipping.")
                continue

            logging.info(f"Retrieved {len(audit_logs)} audit logs from BloodHound for '{current_tenant_domain}'.")

            # 6. Get Bearer Token for Azure Monitor
            azure_monitor_token = bloodhound_manager.get_bearer_token()
            if not azure_monitor_token:
                logging.error("Failed to obtain Bearer token for Azure Monitor. Aborting log submission for this environment.")
                continue

            # 7. Send Audit Logs to Azure Monitor
            successful_submissions, failed_submissions = send_audit_logs_to_azure_monitor(
                audit_logs, bloodhound_manager, azure_monitor_token, current_tenant_domain
            )

            logging.info(f"Audit log submission for '{current_tenant_domain}' complete. Successful: {successful_submissions}, Failed: {failed_submissions}.")

            # 8. Update the last processed timestamp in the Durable Entity
            if successful_submissions > 0:
                new_last_timestamp = max(log["created_at"] for log in audit_logs if "created_at" in log)

                print(f"New last audit logs timestamp after processing: {new_last_timestamp}")
                
                last_audit_logs_timestamp[current_tenant_domain] = new_last_timestamp
                logging.info(f"Updated last processed timestamp for '{current_tenant_domain}' to {new_last_timestamp}.")
            else:
                logging.info(f"No successful submissions for '{current_tenant_domain}'. Last processed timestamp remains unchanged.")
            logging.info(f"--- Finished audit log collection for environment '{current_tenant_domain}' ---\n")

        logging.info("All environments processed. No more environments to process.")
        print(f"Final last_audit_logs_timestamp: {last_audit_logs_timestamp}")
        return last_audit_logs_timestamp
    except KeyError as e:
        logging.error(f"Missing one or more required environment variables: {e}. Exiting process.")
        return
    except Exception as ex:
        logging.error(f"Unexpected Error occurred. {ex}")
        return

def send_audit_logs_to_azure_monitor(audit_logs, bloodhound_manager, azure_monitor_token, current_tenant_domain):
    """
    Sends audit logs to Azure Monitor and returns the count of successful and failed submissions.
    """
    successful_submissions = 0
    failed_submissions = 0
    print(f"Total length of audit logs to process: {len(audit_logs)}")
    if len(audit_logs) > 0:
        for log_entry in audit_logs:
            try:
                logging.info(f"Processing log entry: ID {log_entry.get('id')}")
                result = bloodhound_manager.send_audit_logs_data(log_entry, azure_monitor_token)
                print(f"Result: {result}")
                if result.get("status") == "success":
                    successful_submissions += 1
                else:
                    failed_submissions += 1
                    logging.error(f"Failed to send audit log ID {log_entry.get('id')}: {result.get('message', 'Unknown error')}")
                time.sleep(0.1)
            except Exception as e:
                failed_submissions += 1
                logging.error(f"Exception while sending audit log ID {log_entry.get('id')}: {e}")

    logging.info(
        f"Audit log processing for '{current_tenant_domain}' complete. Successful: {successful_submissions}, Failed: {failed_submissions}."
    )
    return successful_submissions, failed_submissions