"""
This script provides various functions for displaying
analysed/ extracted network packet data,
including generating visualisations, extracted geolocation
data, summarising IP addresses, packet types, and
extracted specific information such as emails and images.
The script decorator seperates data section
presented in the terminal.

Modules imported:
- `matplotlib.pyplot`
(https://matplotlib.org/stable/api/pyplot_summary.html):
        For generating visualisations.
- `pandas.DataFrame`
(https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.html):
        For creating and manipulating data tables.
"""

import logging
import os

import matplotlib.pyplot as plt
from pandas import DataFrame as df

from utils import script_decorator, LOG_FILENAME
from data_extraction import extract_geolocation_data
from data_analysis import Analysis

logger = logging.getLogger("utils")


@script_decorator
def generate_packet_count_chart(analysis: Analysis) -> None:
    """
    Plots the number of packets over time after grouping into intervals.

    Parameters:
        analysis (Analysis): An instance of the Analysis class containing
                             `zip_object` (tuple of times and counts)
                             and a threshold value.

    Saves the chart as a PNG file in the current directory.
    """

    try:

        times, counts = analysis.zip_object
        threshold = analysis.threshold

        # Plotting
        plt.figure(figsize=(10, 6))
        plt.plot(times, counts, marker='o', label='Packet Counts')
        plt.xticks(rotation=45)
        plt.axhline(
            y=threshold,
            color='r',
            linestyle='--',
            label=f'Threshold for exceptionally heavy traffic: {threshold}'
        )
        plt.xlabel('Time')
        plt.ylabel('Number of Packets')
        plt.title('Number of Packets vs Time')
        plt.legend()
        plt.tight_layout()

        png_file = 'number_of_packets_vs_time.png'
        plt.savefig(png_file)

        cwd = os.getcwd()
        png_path = os.path.join(cwd, png_file)

        print(f"Chart saved as PNG: {png_path}")
        logger.info("Chart saved as PNG: %s", png_path)

        plt.show()

    except (TypeError, ValueError) as e:
        logger.error('%s: %s', e.__class__.__name__, e)


@script_decorator
def generate_kml_file(ip_dict: dict) -> None:
    """
    Generates a KML file with geolocation data based on IP addresses.

    Parameters:
        ip_dict (dict): Dictionary of IP addresses and their geolocation data.

    """
    try:

        kml_filename = "pcap_analyser.kml"

        # count processed ip addresses
        total_dict = len(ip_dict)
        # Add data to KML

        # Save the KML file
        ip_count = extract_geolocation_data(ip_dict, kml_filename)
        if ip_count == 0:
            raise RuntimeError("failed to extract geolocation data")

        # Get the current working directory
        cwd = os.getcwd()

        # Join with cwd for full path
        log_path = os.path.join(cwd, LOG_FILENAME)
        kml_path = os.path.join(cwd, kml_filename)

        result_message = (
            f"KML file path: {kml_path}\n\n"
            f"{total_dict} IP addresses extracted from pcap file.\n"
            f"Geo location data found from {ip_count} IP addresses."
            f"\nRemaining {total_dict - ip_count} are likely private"
            f" or not destination IP addresses"
            f"\nview log file to confirm:\n\n{log_path}"
        )
        print(result_message)
        logger.info("Generated KML file: %s", kml_path)
    except OSError as e:
        logger.error("OSError: %s", e)

    except RuntimeError as e:
        logger.error("RuntimeError: %s", e)


@script_decorator
def ip_address_count(ip_dict: dict) -> None:
    """
        Extract the sender and destination IP address pairs for all packets
        and count how many packets were sent from/to each.
        return in form of a dictionary and print sorted by traffic
    """
    try:
        # Convert dict to DataFrame
        data_f = df.from_dict(ip_dict, orient='index')

        # Add a new column for the sum of 'src_count' and 'dst_count'
        data_f['traffic'] = data_f['src_count'] + data_f['dst_count']

        # Sort by 'traffic' in descending order
        df_sorted = data_f.sort_values(by='traffic', ascending=False)

        print(df_sorted)
        logger.info("Succesfully printed IP count table to terminal")

    except ValueError as e:
        logger.error("ValueError: %s", e)
    except KeyError as e:
        logger.error('missing ip in packet: %s', e)


@script_decorator
def packet_types(data: list[dict]) -> None:
    """
    Analyzes packet types and generates a summary table.
    Prints summary table to console

    """

    try:

        # Create DataFrame
        data_frame = df(data)

        # Validate required columns
        required_columns = {'ip_type', 'length', 'time_stamp'}
        if not required_columns.issubset(data_frame.columns):
            raise ValueError("Data is missing one or more required columns")

        # Grouping by 'ip_type' and counting occurrences
        group = data_frame.groupby('ip_type')

        # Aggregate pandas functions - size, mean,
        # first and last to grouped data
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
        print(table.reset_index().to_string(index=False))
        logger.info("successfully printed packet types data table to terminal")

    except ValueError as e:
        logger.error("ValueError: %s", e)

    except TypeError as e:
        logger.error("TypeError: %s", e)


@script_decorator
def extracted_emails(data: list[dict]) -> None:
    """
    Extracts and displays email addresses from packet data.

    Prints:
    - Extracted emails in 'To' and 'From' columns.
    - Unique email addresses found in both fields
    """
    try:
        # Filter data with emails
        f_data = [p for p in data if 'email_to' in p or 'email_from' in p]
        # Create DataFrame
        data_frame = df(f_data)

        # Validate required columns
        required_cols = ['email_from', 'email_to']
        if not all(column in data_frame.columns for column in required_cols):
            raise ValueError("Data is missing one or more required columns")

        # Show extracted emails
        print(data_frame[required_cols].to_string(index=False))

        # Show Unique emails
        print("\n########### Unique Emails From ############\n")
        emails_from = [p['email_from'] for p in f_data]
        for e in list(set(emails_from)):
            print(e)
        print("\n########### Unique Emails To ############\n")
        emails_to = [p['email_to'] for p in f_data]
        for e in list(set(emails_to)):
            print(e)

        logger.info(
            "successfully printed extracted emails data table to terminal")
    except (TypeError, ValueError) as e:
        logger.error("%s: %s", e.__class__.__name__, e)


@script_decorator
def extracted_images(data: list[dict]) -> None:
    """
    Extracts and displays image file names and URLs from packet data.
    """

    try:
        image_count = 0
        for p in data:
            if 'image' in p:
                print(f"File Name: {p['image']}")
                print(f"URL: {p['image_url']}\n")
                image_count += 1

        logger.info(
            "successfully printed name and url for %s images", image_count
        )

    except KeyError as e:
        logger.error("Missing image_url: %s", e)
    except (TypeError, ValueError) as e:
        logger.error("%s: %s", e.__class__.__name__, e)
