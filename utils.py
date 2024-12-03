"""
    utils.py

    util functions for use in pcap_analyser.py

    Third party module documentaion:
    dpkt - https://dpkt.readthedocs.io/en/latest/

"""

import logging
from datetime import datetime as dt
from typing import Callable
import socket
import dpkt

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


def get_pcap_data(pcap_file: str) -> list[dict]:
    """ 
    Reads data from a .pcap file, decodes it, and returns a list of packet details as dictionaries.
    """
    try:
        # Define dpkt variables outside the loop for optimization
        dpkt_eth = dpkt.ethernet.Ethernet
        dpkt_ip = dpkt.ip.IP
        dpkt_tcp = dpkt.tcp.TCP
        dpkt_req = dpkt.http.Request
        dpkt_error = dpkt.UnpackError
        socket_inet_ntoa = socket.inet_ntoa

        # Open and process the pcap file
        data = []
        with open(pcap_file, 'rb') as f:

            pcap = dpkt.pcap.Reader(f)

            for ts, buff in pcap:
                try:
                    eth = dpkt_eth(buff)

                    if isinstance(eth.data, dpkt_ip):
                        packet = {}
                        ip = eth.data

                        # Format the timestamp
                        packet['time_stamp'] = dt.fromtimestamp(
                            ts).replace(microsecond=0)

                        # Decode source and destination IP addresses
                        packet['src_ip'] = socket_inet_ntoa(ip.src)
                        packet['dst_ip'] = socket_inet_ntoa(ip.dst)

                        # Get IP length
                        packet['length'] = ip.len

                        # Add the name of the IP type (UDP/ TCP / ICMP / Other)
                        packet['ip_type'] = type(ip.data).__name__

                        # Check if the payload is TCP and has an HTTP request
                        if isinstance(ip.data, dpkt_tcp):
                            tcp = ip.data
                            try:
                                packet['http_req'] = dpkt_req(tcp.data)
                            except dpkt_error:
                                # Skip TCP packets that do not contain HTTP requests
                                pass
                        data.append(packet)

                except dpkt_error as e:
                    logging.warning("failed to parse data: %s", e)
                    continue
                except Exception as e:
                    logging.error("Error processing packet: %s", e)
                    continue

        return data

    except FileNotFoundError:
        logging.error("The specified pcap file was not found.")
    except PermissionError as e:
        logging.error(
            "Permission denied while trying to open the pcap file: %s", e)
    except ValueError as e:
        logging.error("Incorrect file type: %s", e)
    except dpkt_error as e:
        logging.error("Failed to parse pcap file: %s", e)
    except Exception as e:
        logging.error("An unexpected error occurred: %s", e)
    return []
