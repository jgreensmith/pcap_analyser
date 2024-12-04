"""
sort this
"""

import socket
import os
import re
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


def tcp_handler(tcp, packet: dict) -> None:
    """ filter packets that are to are may contain relevant data"""

    email_from_pattern = r"FROM:\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>"
    email_to_pattern = r"T0:\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>"
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif',
                        '.bmp', '.webp', '.svg'}  # use set for speed
    payload = tcp.data

    # Search
    try:

        try:
            decoded_http = DpktReq(payload)
            # Search for image URLs
            if decoded_http.method == "GET":
                uri = decoded_http.uri.lower()

                # Check if the URI ends with an image extension
                if any(uri.endswith(ext) for ext in image_extensions):
                    packet["image_url"] = f"http{
                        's' if tcp.dport == 443 else ''}://{decoded_http.headers['host']}{uri}"
                    packet["image"] = os.path.basename(uri)

            # code above works, packet wont contain emails so just skip
            return None

        except DpktError:
            # Skip TCP packets that do not contain HTTP requests
            pass

        # Emails
        decoded_payload = payload.decode()
        # Search for email "From" patterns
        email_from = re.findall(email_from_pattern, decoded_payload)
        if email_from:
            packet["email_from"] = email_from[0]

        # Search for email "To" patterns
        
        email_to = re.findall(email_to_pattern, decoded_payload)
        if email_to:
            packet["email_to"] = email_to[0]

        # print(decoded_payload)
    except re.error as e:
        # Skip packets that failed decoding
        logger.error("Regex error occured: %s", e)
    except UnicodeDecodeError:
        # ignore failed decoding errors
        pass


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
    except Exception as e:
        logger.error("An unexpected error occurred: %s", e)
    return []
