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
from data_display import show_packet_types, create_data_frame
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
        data_frame = create_data_frame(data)
        if data_frame.empty:
            raise SafeExitError('create_data_frame')
        show_packet_types(data_frame)

        # print([p for p in data if 'email_to' in p])
        # print([p for p in data if 'email_from' in p])
        # print([p['image'] for p in data if 'image_url' in p])
    except SafeExitError as e:
        print(f"Caught SafeExitError: {e}")
        logger.warning('Caught SafeExitError script ended safely')


if __name__ == "__main__":
    main()
