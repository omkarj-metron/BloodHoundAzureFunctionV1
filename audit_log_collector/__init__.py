import logging
import os
import json
import azure.functions as func
from ..SharedCode.azure_functions.audit_log_collector import bloodhound_audit_logs_collector_main_function

# Path to state.json inside the same directory as __init__.py
STATE_FILE = os.path.join(os.path.dirname(__file__), "state.json")

def read_state():
    """Read the state from state.json. Return {} if file is empty or invalid."""
    if not os.path.exists(STATE_FILE):
        with open(STATE_FILE, "w") as f:
            json.dump({}, f)
        return {}

    try:
        with open(STATE_FILE, "r") as f:
            content = f.read().strip()
            if not content:
                logging.warning("state.json is empty. Initializing with {}.")
                return {}
            return json.loads(content)
    except (json.JSONDecodeError, ValueError) as e:
        logging.warning(f"state.json is invalid ({e}). Resetting to empty dict.")
        with open(STATE_FILE, "w") as f:
            json.dump({}, f)
        return {}


def write_state(state):
    """Write updated state to state.json"""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def main(myTimer: func.TimerRequest):
    logging.info("Timer triggered: bloodhound_audit_logs_collector executed.")

    if myTimer.past_due:
        logging.warning("The timer trigger is past due!")

    # Read previous state
    state = read_state()
    last_audit_logs_timestamp = state.get("last_audit_logs_timestamp", {})  # Use {} if key missing
    logging.info(f"Last value from state.json: {last_audit_logs_timestamp}")

    # Call main function with last value
    new_audit_logs_timestamp = bloodhound_audit_logs_collector_main_function(last_audit_logs_timestamp)
    logging.info(f"New value from collector: {new_audit_logs_timestamp}")

    # Update state.json
    state["last_audit_logs_timestamp"] = new_audit_logs_timestamp
    write_state(state)
    logging.info(f"State updated in state.json: {new_audit_logs_timestamp}")

    logging.info("bloodhound_audit_logs_collector execution finished.")
