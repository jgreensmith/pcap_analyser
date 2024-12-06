"""
    pcap_analyser.py

    Script to open a packet capture (pcap file) and parse
    using dpkt for specified information such as IP and email addresses.
    It will also perform statistical analysis on the contents and visualise the traffic flows

    Third party module documentaion:
    pandas - 
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

        data = get_pcap_data(file)
        if not data:
            raise SafeExitError('get_pcap_data')
        packet_types(data)
        extracted_emails(data)
        extracted_images(data)
        ip_dict = get_ip_dict(data)
        if ip_dict is None:
            raise SafeExitError('get_ip_dict')
        ip_address_count(ip_dict)
        generate_kml_file(ip_dict)
        analysis = traffic_time_analysis(data)
        if analysis is None:
            raise SafeExitError('traffic_time_analysis')
        generate_packet_count_chart(analysis)

    except SafeExitError as e:
        print(f"Caught SafeExitError: {e}")
        logger.warning('Caught SafeExitError script ended safely')


if __name__ == "__main__":
    main()
