""" sort this"""

import os
import re
import logging
import dpkt


logger = logging.getLogger("utils")

DpktReq = dpkt.http.Request
DpktError = dpkt.UnpackError


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
