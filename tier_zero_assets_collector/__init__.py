import logging
import azure.functions as func
import azure.durable_functions as df

import logging
import time

from ..SharedCode.azure_functions.tier_zero_assets_collector import run_tier_zero_assets_collection_process

def main(myTimer: func.TimerRequest) -> None:
    if myTimer.past_due:
        logging.info('The timer is past due!')

    print("Starting tier zero assets collector function")

    run_tier_zero_assets_collection_process()
