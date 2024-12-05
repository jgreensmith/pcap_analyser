"""
sort this
"""
import logging
from pandas import DataFrame as df
import geoip2.database
import simplekml
from utils import script_decorator

logger = logging.getLogger("utils")


@script_decorator
def generate_kml_file(ip_dict: dict) -> None:
    """ generate KML file"""

    reader = geoip2.database.Reader(r"GeoLite2-City_20190129.mmdb")
    print(reader.city("146.176.164.91"))
    # rec = reader.
    # ("146.176.164.91")
    # print(rec.location)

    # # Create a KML object
    # kml = simplekml.Kml()

    # # Add data to KML
    # for ip, counts in ip_dict.items():
    #     total_count = counts['src_count'] + counts['dst_count']
    #     if ip in coordinates:
    #         lat, lon = coordinates[ip]
    #         pnt = kml.newpoint(name=f"{ip}", coords=[(lon, lat)])
    #         pnt.description = f"Total Count: {total_count}"
    #         pnt.style.labelstyle.color = simplekml.Color.red
    #         pnt.style.labelstyle.scale = 1

    # # Save the KML file
    # kml.save("output.kml")


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
    """ generate a table showing type of IP (UDP/TCP),
        total packets and mean packet length
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
        print(table.reset_index().to_string(index=False))
        logger.info("successfully printed packet types data table to terminal")

    except ValueError as e:
        logger.error("ValueError: %s", e)

    except TypeError as e:
        logger.error("TypeError: %s", e)


@script_decorator
def extracted_emails(data: list[dict]) -> None:
    """ show extracted emails in columns To and From. 
        Using 'or' in the filter instead of 'and', 
        this is so if a packet has failed to extract an email
        address, it will be caught as a value error below.
    """
    try:
        # Filter data with emails
        f_data = [p for p in data if 'email_to' in p or 'email_from' in p]
        # Create DataFrame
        data_frame = df(f_data)

        # Validate required columns
        required_columns = ['email_from', 'email_to']
        if not all(column in data_frame.columns for column in required_columns):
            raise ValueError("Data is missing one or more required columns")

        # Show extracted emails
        print(data_frame[required_columns].to_string(index=False))

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
    """ show extracted image file names and full urls"""
    try:

        for p in data:
            if 'image' in p:
                print(f"File Name: {p['image']}")
                print(f"URL: {p['image_url']}\n")

        logger.info("successfully printed image name and files to terminal")

    except KeyError as e:
        logger.error("Missing image_url: %s", e)
    except (TypeError, ValueError) as e:
        logger.error("%s: %s", e.__class__.__name__, e)
