"""
This script processes and analyses network traffic data from .pcap files. 
It includes utilities for decoding packets, extracting IP address details, 
and organising packet information for further analysis.

Third Party Modules imported:
  - `dpkt` (https://dpkt.readthedocs.io/en/latest/): 
    For reading and parsing .pcap files, and handling network packet structures.
"""

import socket
import logging
from datetime import datetime as dt
import dpkt
from data_extraction import tcp_handler

logger = logging.getLogger("utils")


# Define dpkt callable classes and socket function outside the loop for optimization
DpktEth = dpkt.ethernet.Ethernet
DpktIp = dpkt.ip.IP
DpktTcp = dpkt.tcp.TCP
DpktReq = dpkt.http.Request
DpktError = dpkt.UnpackError
socket_inet_ntoa = socket.inet_ntoa


def get_ip_dict(data: list[dict]) -> dict | None:
    """
        Extract the sender and destination IP address pairs for all packets 
        and count how many packets were sent from/to each.
        return in form of a dictionary and print sorted by traffic
    """

    try:
        ip_dict = {}
        for p in data:
            # add src ip to count or add new object
            if p['src_ip'] in ip_dict:
                ip_dict[p['src_ip']]['src_count'] += 1
            else:
                ip_dict[p['src_ip']] = {'src_count': 1, 'dst_count': 0}

            # add dst ip to count or add new object
            if p['dst_ip'] in ip_dict:
                ip_dict[p['dst_ip']]['dst_count'] += 1
            else:
                ip_dict[p['dst_ip']] = {'src_count': 0, 'dst_count': 1}

        logger.info('Successfully generated ip_dict')
        return ip_dict
    except ValueError as e:
        logger.error("ValueError: %s", e)
    except KeyError as e:
        logger.error('missing ip in packet: %s', e)
    return None


def get_pcap_data(pcap_file: str) -> list[dict]:
    """ 
    Reads data from a .pcap file, decodes it, and returns a list of packet details as dictionaries.
    """
    try:

        # Open and process the pcap file
        data = []
        with open(pcap_file, 'rb') as f:

            pcap = dpkt.pcap.Reader(f)

            logger.info("file %s read succesfully", pcap_file)

            for ts, buff in pcap:
                try:
                    eth = DpktEth(buff)

                    if isinstance(eth.data, DpktIp):
                        packet = {}
                        ip = eth.data

                        # Format the timestamp
                        packet['time_stamp'] = dt.fromtimestamp(
                            ts).replace(microsecond=0)

                        # Decode source and destination IP addresses
                        packet['src_ip'] = socket_inet_ntoa(ip.src)
                        packet['dst_ip'] = socket_inet_ntoa(ip.dst)

                        # Get full packet length length
                        packet['length'] = len(buff)

                        # Add the name of the IP type (UDP/ TCP / ICMP / Other)
                        packet['ip_type'] = type(ip.data).__name__

                        # Check if the payload is TCP for payload analysis
                        if isinstance(ip.data, DpktTcp):
                            tcp = ip.data
                            tcp_handler(tcp, packet)

                        data.append(packet)

                except DpktError as e:
                    logger.warning("failed to parse packet %s: %s", ts, e)
                    continue

        return data

    except FileNotFoundError:
        logger.error("The specified pcap file was not found.")
    except PermissionError as e:
        logger.error(
            "Permission denied while trying to open the pcap file: %s", e)
    except ValueError as e:
        logger.error("Incorrect file type: %s", e)
    except DpktError as e:
        logger.error("Failed to parse pcap file: %s", e)
    return []
