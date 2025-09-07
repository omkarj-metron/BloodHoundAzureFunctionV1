import logging
import time
from datetime import datetime, timedelta
from azure.core.exceptions import ResourceNotFoundError
from ..utility.utils import fetch_env_variables, get_token_lists

from ..utility.bloodhound_manager import BloodhoundManager

def send_finding_trends_to_azure_monitor(all_findings_to_send, bloodhound_manager, azure_monitor_token, current_tenant_domain, domains_data):
    """
    Sends finding trends data to Azure Monitor and returns the count of successful and failed submissions.
    """
    successful_submissions = 0
    failed_submissions = 0

    if all_findings_to_send:
        logging.info(f"Sending {len(all_findings_to_send)} collected finding trends to Azure Monitor.")
        for i, item in enumerate(all_findings_to_send, 1):
            data = item["finding"]
            period = item["period"]
            env_id_for_log = item["environment_id"]
            try:
                result = bloodhound_manager.send_finding_trends_logs(
                    data, azure_monitor_token, current_tenant_domain, domains_data,
                    environment_id=env_id_for_log,
                    start_date=item["start_date"],
                    end_date=item["end_date"],
                    period=period
                )

                print(f"Processing finding trends log entry {i}/{len(all_findings_to_send)}: {data.get('finding')} in environment ID {env_id_for_log}")
                print(f"Result of sending finding trends log for '{data.get('finding')}' is {result}")
                logging.info(f"Result of sending finding trends log for '{data.get('finding')}' is {result}")
                if result.get("status") == "success":
                    successful_submissions += 1
                else:
                    failed_submissions += 1
                    logging.error(f"Failed to send finding trends log for '{data.get('finding')}': {result.get('message', 'Unknown error')}")
            except Exception as e:
                failed_submissions += 1
                logging.error(f"Exception while sending finding trends log for '{data.get('finding')}': {e}")
            time.sleep(0.1)

        logging.info(f"Finding trends processing for '{current_tenant_domain}' complete. Successful submissions: {successful_submissions}, Failed submissions: {failed_submissions}.")
    else:
        logging.info("No finding trends were collected to send to Azure Monitor for this environment.")
    
    return successful_submissions, failed_submissions


def run_finding_trends_collection_process() -> bool:
    """
    Orchestrates the entire BloodHound finding trends collection and Azure Monitor submission process
    for multiple environments, handling each sequentially.
    Returns True if successful, False otherwise.
    """
    logging.info("Starting BloodHound finding trends collection process.")
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
            "FINDING_TRENDS_TABLE_NAME",
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
        table_name = env_vars["FINDING_TRENDS_TABLE_NAME"]
        key_vault_url = env_vars["KEY_VAULT_URL"]
        token_id = env_vars["BLOODHOUND_TOKEN_ID"]
        token_key = env_vars["BLOODHOUND_TOKEN_KEY"]

        logging.info(f"Configuration loaded for finding trends. Key Vault URL: {key_vault_url}")

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

        if not (len(list_tenant_domains) == len(all_token_ids) == len(all_token_keys)):
            logging.error("Environment variable lists for domains, token IDs, and token keys have a mismatch in length. Exiting.")
            return

        num_environments = len(list_tenant_domains)
        logging.info(f"Identified {num_environments} BloodHound environments to process.")

        selected_bhe_environments = env_vars["SELECTED_BLOODHOUND_ENVIRONMENTS"]

        # Loop through each environment
        for i in range(num_environments):
            current_tenant_domain = list_tenant_domains[i]
            current_token_id = all_token_ids[i]
            current_token_key = all_token_keys[i]

            logging.info(f"\n--- Starting finding trends collection for environment '{current_tenant_domain}' ---")

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
                return

            logging.info(f"BloodHound API connection test passed for '{current_tenant_domain}'. Starting collection...")

            # 5. Get available domains from BloodHound
            res_domains = bloodhound_manager.get_available_domains()
            if not res_domains:
                logging.error("Failed to fetch available domains. Cannot proceed with finding trends.")
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

            # 6. Get Bearer Token for Azure Monitor
            azure_monitor_token = bloodhound_manager.get_bearer_token()
            if not azure_monitor_token:
                logging.error("Failed to obtain Bearer token for Azure Monitor. Aborting submission for this environment.")
                continue

            # Define the timeframes in days
            time_frames_in_days = [365, 180, 90, 30, 7]
            TIME_PERIOD_MAP = {
                365: "1 year",
                180: "6 months",
                90: "3 months",
                30: "1 month",
                7: "1 week"
            }
            all_findings_to_send = []

            # Iterate over each timeframe and environment
            for days in time_frames_in_days:
                start_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
                for env_id in environment_ids:
                    logging.info(f"Fetching finding trends for environment ID: {env_id} for period of {days} days")
                    finding_trends_response = bloodhound_manager.get_finding_trends(
                        environment_id=env_id, start_date=start_date
                    )

                    if finding_trends_response and finding_trends_response.get("data", {}).get("findings"):
                        start_date_from_api = finding_trends_response.get("start", "")
                        end_date = finding_trends_response.get("end", "")
                        finding_trends_findings = finding_trends_response.get("data").get("findings", [])
                        
                        logging.info(f"Found {len(finding_trends_findings)} findings for {env_id} in {days} days period")
                        for finding in finding_trends_findings:
                            all_findings_to_send.append({
                                "finding": finding,
                                "environment_id": env_id,
                                "start_date": start_date_from_api,
                                "end_date": end_date,
                                "period": TIME_PERIOD_MAP.get(days, f"{days} days"),
                            })
                    else:
                        logging.warning(f"No finding trends found for environment ID: {env_id} for {days} days period.")

            successful_submissions = 0
            failed_submissions = 0

            successful_submissions, failed_submissions = send_finding_trends_to_azure_monitor(
                all_findings_to_send,
                bloodhound_manager,
                azure_monitor_token,
                current_tenant_domain,
                domains_data
            )

            logging.info(f"Successful submissions: {successful_submissions} & Failed submissions: {failed_submissions}")

        logging.info("BloodHound finding trends collection process finished for all environments.")

    except KeyError as e:
        logging.error(f"Missing one or more required environment variables: {e}. Exiting process.")
    except ResourceNotFoundError as e:
        logging.error(f"Resource not found in Azure Key Vault: {e}. Exiting process.")
    except Exception as ex:
        logging.error(f"Unexpected error occurred: {ex}")