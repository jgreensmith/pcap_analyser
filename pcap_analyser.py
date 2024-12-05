"""
    pcap_analyser.py

    Script to open a packet capture (pcap file) and parse
    using dpkt for specified information such as IP and email addresses.
    It will also perform statistical analysis on the contents and visualise the traffic flows

    Third party module documentaion:
    pandas - 
"""

import logging
from data_aggregation import get_pcap_data
from data_display import packet_types, extracted_emails, extracted_images, ip_address_count
from utils import SafeExitError

logger = logging.getLogger("utils")


def main():
    """function for primary script logic """
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
        ip_address_count(data)

        # print([p for p in data if 'email_to' in p])
        # print([p for p in data if 'email_from' in p])
        # print([p['image'] for p in data if 'image_url' in p])
    except SafeExitError as e:
        print(f"Caught SafeExitError: {e}")
        logger.warning('Caught SafeExitError script ended safely')


if __name__ == "__main__":
    main()
