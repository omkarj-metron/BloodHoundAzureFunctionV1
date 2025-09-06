import logging
import azure.functions as func
import azure.durable_functions as df

import logging
import time

from ..SharedCode.azure_functions.finding_trends_collector import run_finding_trends_collection_process

def main(myTimer: func.TimerRequest) -> None:
    if myTimer.past_due:
        logging.info('The timer is past due!')

    print("Starting finding trends collector function")
    
    run_finding_trends_collection_process()
