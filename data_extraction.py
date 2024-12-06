"""
This script contains functions for the extraction
process of the packet capture analysis.
extracting geolocation data, images, and
email information from the packets.

Third Party Modules imported:
    - `dpkt` (https://dpkt.readthedocs.io/en/latest/):
        For reading and parsing .pcap files,
        and handling network packet structures.
    - `simplekml` (https://simplekml.readthedocs.io/en/latest/):
        For interacting with kml object - can
        create files to be used on google earth.
    - `geoip2` (https://pypi.org/project/geoip2/):
        For obtaining geolocation data from ip addresses.
"""

import os
import re
import logging
import dpkt
import simplekml
import geoip2.errors
import geoip2.database


logger = logging.getLogger("utils")

DpktReq = dpkt.http.Request
DpktError = dpkt.UnpackError


def extract_geolocation_data(ip_dict: dict, kml_filename: str) -> int:
    """ search geoip2 database for every destination ip address in ip_dict """

    ip_count = 0
    try:

        reader = geoip2.database.Reader(r"GeoLite2-City_20190129.mmdb")

        # Create a KML object
        kml = simplekml.Kml()
        AddressNotFoundError = geoip2.errors.AddressNotFoundError

        for ip, counts in ip_dict.items():
            if counts['dst_count'] > 0:
                try:
                    # Read from geoip2 database to obtain geo data
                    geo_data = reader.city(ip)

                    city = geo_data.city.name
                    country = geo_data.country.name
                    lon = geo_data.location.longitude
                    lat = geo_data.location.latitude

                    pnt = kml.newpoint(name=f"{ip}", coords=[(lon, lat)])
                    pnt.description = (
                        f"Destination IP address count: {
                            counts['dst_count']}\n"
                        f"City: {city}\n"
                        f"Country: {country}"
                    )

                    pnt.style.labelstyle.color = simplekml.Color.red
                    pnt.style.labelstyle.scale = 1

                    ip_count += 1
                except AddressNotFoundError as e:
                    logger.warning("%s not in geoip2 database", e)
            else:
                logger.warning("%s is not in destination ip address", ip)
        kml.save(kml_filename)

    except geoip2.errors.GeoIP2Error as e:
        logger.error("Error reading geoip2 database: %s", e)
    return ip_count


def extract_image(dpkt_req: dpkt.http.Request, packet: dict, port: int) -> None:
    """
    check if http request contains and image,
    then add url and image name to packet
    """
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif',
                        '.bmp', '.webp', '.svg'}  # use set for speed

    if dpkt_req.method == "GET":
        uri = dpkt_req.uri.lower()

        # Check if the URI ends with an image extension
        if any(uri.endswith(ext) for ext in image_extensions):

            packet["image_url"] = (
                f"http{'s' if port == 443 else ''}"
                f"://{dpkt_req.headers['host']}{uri}"
            )
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
