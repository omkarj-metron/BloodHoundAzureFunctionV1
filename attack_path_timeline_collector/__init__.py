import logging
import os
import json
import azure.functions as func

from ..SharedCode.azure_functions.attack_path_timeline_collector import run_attack_paths_timeline_collection_process

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
    logging.info("Timer triggered: attack_path_timeline_collector executed.")

    if myTimer.past_due:
        logging.warning("The timer trigger is past due!")

    # Read previous state
    state = read_state()
    last_attack_path_timeline_timestamp = state.get("last_attack_path_timeline_timestamp", {})

    logging.info(f"Last attack path timeline timestamp from state.json: {last_attack_path_timeline_timestamp}")

    # Call main function with last value and capture new timestamp
    print(f"type of last_attack_path_timeline_timestamp: {type(last_attack_path_timeline_timestamp)}")
    print(f"last_attack_path_timeline_timestamp: {last_attack_path_timeline_timestamp}")
    new_attack_path_timeline_timestamp = run_attack_paths_timeline_collection_process(last_attack_path_timeline_timestamp)
    logging.info(f"New attack path timeline timestamp: {new_attack_path_timeline_timestamp}")

    # Update state.json
    state["last_attack_path_timeline_timestamp"] = new_attack_path_timeline_timestamp
    write_state(state)
    logging.info(f"State updated in state.json: {new_attack_path_timeline_timestamp}")

    logging.info("attack_path_timeline_collector execution finished.")
