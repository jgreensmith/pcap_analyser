"""
sort this
"""
import logging
from pandas import DataFrame as df
from utils import script_decorator

logger = logging.getLogger("utils")


def create_data_frame(data: list[dict]) -> df | None:
    """use pandas to create data frame"""

    try:
        data_frame = df(data)
        # Create DataFrame
        return data_frame

    except ValueError as e:
        logger.error("ValueError: %s", e)
    except TypeError as e:
        logger.error("TypeError: %s", e)
    return None


@script_decorator
def show_packet_types(data_frame: df) -> None:
    """ generate a table showing type of IP (UDP/TCP),
        total packets and mean packet length
       """

    try:

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
        print(table.reset_index())
        logger.info("successfully printed packet types data table to terminal")

    except ValueError as e:
        logger.error("ValueError: %s", e)

    except TypeError as e:
        logger.error("TypeError: %s", e)
