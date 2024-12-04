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
