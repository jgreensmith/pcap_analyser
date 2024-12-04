"""
sort this
"""

import socket
import logging
from datetime import datetime as dt
import dpkt

logger = logging.getLogger("utils")


# Define dpkt callable classes and socket function outside the loop for optimization
DpktEth = dpkt.ethernet.Ethernet
DpktIp = dpkt.ip.IP
DpktTcp = dpkt.tcp.TCP
DpktReq = dpkt.http.Request
DpktError = dpkt.UnpackError
socket_inet_ntoa = socket.inet_ntoa


def tcp_handler(tcp: DpktTcp, packet: dict) -> None:
    """ filter packets that are to are may contain relevant data"""

    # Search for HTTP requests
    try:
        packet['http_req'] = DpktReq(tcp.data)
    except DpktError:
        # Skip TCP packets that do not contain HTTP requests
        pass
    # Search for Emails
    # try:
    #     packet['http_req'] = DpktReq(tcp.data)
    # except DpktError:
    #     # Skip TCP packets that do not contain Emails
    #     pass


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

                        # Check if the payload is TCP and has an HTTP request
                        if isinstance(ip.data, DpktTcp):
                            tcp = ip.data
                            tcp_handler(tcp, packet)

                        data.append(packet)

                except DpktError as e:
                    logger.warning("failed to parse data: %s", e)
                    continue
                except Exception as e:
                    logger.error("Error processing packet: %s", e)
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
    except Exception as e:
        logger.error("An unexpected error occurred: %s", e)
    return []
