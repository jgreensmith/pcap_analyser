"""
utils.py

This script provides the utility functions and
configurations for use in pcap_analyser.
"""

import logging
from datetime import datetime as dt
from typing import Callable

# Configure logging
LOG_FILENAME = f"pcap_analyser_log_{dt.now().strftime('%Y-%m-%d')}.log"

logging.basicConfig(
    filename=LOG_FILENAME,  # Log file name
    level=logging.INFO,     # Set default logging level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
    datefmt='%Y-%m-%d %H:%M:%S'  # Date format
)

# Define the custom exception


class SafeExitError(Exception):
    """Custom exception for safe script termination."""

    def __init__(self, message: str):
        self.message = message
        self.logger_file = LOG_FILENAME
        super().__init__(self.message)

    def __str__(self):
        return (
            f"safely exited early due to an error at: {self.message}"
            f"\nFor troubleshooting, view the log file: {self.logger_file}"
        )


def script_decorator(func: Callable) -> Callable:
    """ format the terminal output"""

    spacer_max = 85
    title = func.__name__.replace('_', ' ').title()
    spacert = '-' * int((spacer_max - (len(title) + 2)) / 2)
    spacerb = '-' * spacer_max

    def wrapper(*args, **kwargs):
        print(f"\n{spacert} {title} {spacert}\n")
        func(*args, **kwargs)
        print(f"\n{spacerb}")
    return wrapper
