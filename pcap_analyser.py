"""
pcap_analyser.py

Author: James Greensmith
Date: 06 December 2024
Version: 1.0

This script opens, reads and closes a packet capture
(pcap file) and parses specific information:
    - ip addresses
    - email addresses
    - image urls from http get requests
    - packet types (UDP/ TCP/ IGMP)
    - time stamps.

The data is used in various display functions and further
data analysis functions that perform statistical analysis
on the visualise the traffic flows. each function that has a
return statement raises a SafeExitError on fail, safely stopping
the script early.

Files Generated:
    - pcap_analyser_log_<date>.log
    - pcap_analyser.kml
    - number_of_packets_vs_time.png

Instructions:
    - in the root directory, run:
        pip install -r requirements.txt && python -m pcap_analyser.py
"""

import logging
from data_aggregation import get_pcap_data, get_ip_dict
from data_analysis import traffic_time_analysis
from data_display import (
    packet_types,
    extracted_emails,
    extracted_images,
    ip_address_count,
    generate_kml_file,
    generate_packet_count_chart
)
from utils import SafeExitError

logger = logging.getLogger("utils")


def main():
    """function for primary script logic."""
    try:
        # Test cases
        file = 'evidence-packet-analysis.pcap'
        # file = 'missing_file.pcap'
        # file = 'bad_file.pcap'

        # Open, parse and close a pcap file.
        data = get_pcap_data(file)
        if not data:
            raise SafeExitError('get_pcap_data')

        # Display data tables to console
        packet_types(data)
        extracted_emails(data)
        extracted_images(data)

        # Generate IP dictionary based on data from pcap file
        ip_dict = get_ip_dict(data)
        if ip_dict is None:
            raise SafeExitError('get_ip_dict')

        # Process data from IP dictionary and display in console
        ip_address_count(ip_dict)

        # Generate a KML file based on Destination IPs
        generate_kml_file(ip_dict)

        # Carry out statistical analysis on pcap data
        analysis = traffic_time_analysis(data)
        if analysis is None:
            raise SafeExitError('traffic_time_analysis')

        # Display visualisation and generate a .png file
        generate_packet_count_chart(analysis)

    except SafeExitError as e:
        print(f"Caught SafeExitError: {e}")
        logger.warning('Caught SafeExitError script ended safely')


if __name__ == "__main__":
    main()
