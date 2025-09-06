import logging
import os
import json
import azure.functions as func

from ..SharedCode.azure_functions.posture_history_collector import run_posture_history_collection_process

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

def main(myTimer: func.TimerRequest) -> None:
    logging.info("Timer triggered: bloodhound_posture_history_collector executed.")

    if myTimer.past_due:
        logging.warning("The timer trigger is past due!")

    # Read previous state
    state = read_state()
    last_posture_history_timestamp = state.get("last_posture_history_timestamp", {})

    logging.info(f"Last posture history timestamp from state.json: {last_posture_history_timestamp}")

    # Call main function with last value
    new_posture_history_timestamp = run_posture_history_collection_process(last_posture_history_timestamp)
    logging.info(f"New posture history timestamp: {new_posture_history_timestamp}")

    # Update state.json
    state["last_posture_history_timestamp"] = new_posture_history_timestamp
    write_state(state)
    logging.info(f"State updated in state.json: {new_posture_history_timestamp}")

    logging.info("bloodhound_posture_history_collector execution finished.")
