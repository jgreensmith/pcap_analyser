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
from data_display import show_packet_types

logger = logging.getLogger("utils")


def main():
    """function for primary script logic """
    # Test case
    file = 'evidence-packet-analysis.pcap'
    # file = 'pcap_analyser_log_2024-12-03.log'
    # logger.info("butt")
    data = get_pcap_data(file)
    show_packet_types(data)

    print([p for p in data if 'email_to' in p])
    print([p for p in data if 'email_from' in p])
    # print([p['image'] for p in data if 'image_url' in p])


if __name__ == "__main__":
    main()
