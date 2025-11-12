#!/usr/bin/env python3
"""
Zone-Poker - CSV Output Module
"""
import io
import csv
from typing import Dict, Any

from ..config import console
from ..dispatch_table import MODULE_DISPATCH_TABLE


def output(all_data: Dict[str, Any]):
    """
    Prints the scan data to the console in CSV format.
    """
    output_io = io.StringIO()
    writer = csv.writer(output_io)
    writer.writerow(["module_key", "key", "value"])

    for module_name, config in MODULE_DISPATCH_TABLE.items():
        data_key = config["data_key"]
        if data_key in all_data and all_data[data_key]:
            data = all_data[data_key]
            if isinstance(data, dict):
                for key, value in data.items():
                    writer.writerow([data_key, key, str(value)])
            elif isinstance(data, list):
                for item in data:
                    writer.writerow([data_key, "", str(item)])
            else:
                writer.writerow([data_key, "", str(data)])

    console.print(output_io.getvalue())
