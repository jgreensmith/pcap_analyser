"""
This module provides logic for data analysis,
including interval-based packet counts and statistical threshold calculation.

Imports:
    - `logging`: For logging script activities and errors.
    - `datetime.timedelta`: for interacting with datetime object
    - `numpy` (https://numpy.org/doc/stable/reference/index.html#reference):
        For statistical analysis
"""

import logging
from datetime import timedelta
import numpy as np

logger = logging.getLogger("utils")


class Analysis:
    """
    Represents the result of a traffic time analysis.
    """

    def __init__(self, zip_object: zip, threshold: int):
        self.zip_object = zip_object
        self.threshold = threshold


def traffic_time_analysis(data: list[dict], interval_length: int = 2) -> Analysis | None:
    """
    Analyses packet traffic over specified time intervals
    and computes a threshold
    for detecting heavy traffic based on two standard deviations.
    """
    try:
        if interval_length <= 0:
            raise ValueError("Interval length must be a positive integer.")
        # Sort the data by timestamp
        data = sorted(data, key=lambda x: x['time_stamp'])

        # Determine the start and end times for grouping
        start_time = data[0]['time_stamp']
        end_time = data[-1]['time_stamp']

        # Create intervals
        intervals = []
        current_time = start_time
        while current_time <= end_time:
            # increase by variable interval_length
            intervals.append(current_time)
            current_time += timedelta(seconds=interval_length)

        packet_counts = []

        # index over intervals and count packets with time_stamps
        # within each interval
        for i in range(len(intervals) - 1):
            intv = intervals[i]
            next_intv = intervals[i + 1]
            count = len([
                p for p in data if intv <= p['time_stamp'] and
                next_intv > p['time_stamp']
            ])
            packet_counts.append((intv, count))

        # Calculate mean and threshold
        counts = [count for _, count in packet_counts]
        threshold = round((np.mean(counts) + 2 * np.std(counts)), 2)

        # Zip is efficient way of working with tuples
        return Analysis(zip(*packet_counts), threshold)

    except (ValueError, TypeError) as e:
        logger.error('%s: %s', e.__class__.__name__, e)
        return None
