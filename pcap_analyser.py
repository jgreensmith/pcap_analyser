"""
    pcap_analyser.py

    Script to open a packet capture (pcap file) and parse
    using dpkt for specified information such as IP and email addresses.
    It will also perform statistical analysis on the contents and visualise the traffic flows

    Third party module documentaion:
    pandas - 
"""

import logging
from pandas import DataFrame as df
from utils import get_pcap_data, script_decorator

logger = logging.getLogger("utils")


@script_decorator
def show_packet_types(data: list[dict]) -> None:
    """ generate a table showing type of IP (UDP/TCP),
        total packets and mean packet length
       """
    # Creating a DataFrame
    data_table = df(data)

    # Grouping by 'ip_type' and counting occurrences
    group = data_table.groupby('ip_type')

    # Aggregate pandas functions - size, mean, first and last to grouped data
    table = group.agg(
        packet_count=('length', 'size'),
        mean_packet_length=('length', 'mean'),
        first=('time_stamp', 'first'),
        last=('time_stamp', 'last')
    )

    # Round the mean_packet_length to the nearest integer
    table['mean_packet_length'] = table['mean_packet_length'].round(
        0).astype(int)

    # show result
    print(table.reset_index())


def main():
    """function for primary script logic """
    # Test case
    file = 'evidence-packet-analysis.pcap'
    # file = 'pcap_analyser_log_2024-12-03.log'
    # logger.info("butt")
    data = get_pcap_data(file)
    show_packet_types(data)


if __name__ == "__main__":
    main()
