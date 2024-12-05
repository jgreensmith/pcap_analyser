"""
    utils.py

    util functions for use in pcap_analyser.py

    Third party module documentaion:
    dpkt - https://dpkt.readthedocs.io/en/latest/

"""

import logging
from datetime import datetime as dt
from typing import Callable

# Configure logging
log_filename = f"pcap_analyser_log_{dt.now().strftime('%Y-%m-%d')}.log"

logging.basicConfig(
    filename=log_filename,  # Log file name
    level=logging.INFO,     # Set default logging level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
    datefmt='%Y-%m-%d %H:%M:%S'  # Date format
)

# Define the custom exception
class SafeExitError(Exception):
    """Custom exception for safe script termination."""

    def __init__(self, message):
        self.message = message
        self.logger_file = log_filename
        super().__init__(self.message)

    def __str__(self):
        return f"safely exited early due to an error at:{self.message}\nFor troubleshooting, view the log file: {self.logger_file}"


def script_decorator(func: Callable) -> Callable:
    """ format the terminal output"""

    spacer_max = 85
    name = func.__name__
    spacert = '-' * int((spacer_max - (len(name) + 2)) / 2)
    spacerb = '-' * spacer_max

    def wrapper(*args, **kwargs):
        print(f"\n{spacert} {name} {spacert}\n")
        func(*args, **kwargs)
        print(f"\n{spacerb}")
    return wrapper


