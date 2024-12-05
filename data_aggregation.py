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


def extract_image(dpkt_req: DpktReq, packet: dict, port: int) -> None:
    """check if http request contains and image, then add url and image name to packet"""
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif',
                        '.bmp', '.webp', '.svg'}  # use set for speed

    if dpkt_req.method == "GET":
        uri = dpkt_req.uri.lower()

        # Check if the URI ends with an image extension
        if any(uri.endswith(ext) for ext in image_extensions):
            packet["image_url"] = f"http{
                's' if port == 443 else ''}://{dpkt_req.headers['host']}{uri}"
            packet["image"] = os.path.basename(uri)


def extract_emails(decoded_payload: str, packet: dict) -> None:
    """extract emails from decoded payload using regex"""

    try:

        from_pattern = r"From:\s*[\"]?[a-zA-Z\s]+[\"]?\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>"
        to_pattern = r"To:\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>"
        # Search for email "From" patterns
        email_from = re.findall(from_pattern, decoded_payload)
        if email_from:
            packet["email_from"] = email_from[0]

        # Search for email "To" patterns
        email_to = re.findall(to_pattern, decoded_payload)
        if email_to:
            packet["email_to"] = email_to[0]

    except re.error as e:
        logger.error("Regex error occured: %s", e)


def tcp_handler(tcp, packet: dict) -> None:
    """ filter packets that are to are may contain relevant data"""

    payload = tcp.data

    # Search
    try:

        try:
            dpkt_req = DpktReq(payload)
            # Search for image URLs
            extract_image(dpkt_req, packet, tcp.dport)
            # code above works, packet wont contain emails so just skip
            return None

        except DpktError:
            # Skip TCP packets that do not contain HTTP requests
            pass

        # Emails
        decoded_payload = payload.decode()
        extract_emails(decoded_payload, packet)

    except UnicodeDecodeError:
        # ignore failed decoding errors
        pass
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
