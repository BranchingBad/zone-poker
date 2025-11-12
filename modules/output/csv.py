#!/usr/bin/env python3
"""
Zone-Poker - CSV Output Module
"""
import builtins
import csv
import io
from typing import Dict, Any


def output(all_data: Dict[str, Any]):
    """
    Generates and prints a CSV report to standard output.
    This is a simplified example focusing on DNS records.
    """
    output_io = io.StringIO()
    writer = csv.writer(output_io)

    # Header
    writer.writerow(
        ["domain", "scan_timestamp", "record_type", "value", "ttl", "priority"]
    )

    domain = all_data.get("domain", "N/A")
    timestamp = all_data.get("scan_timestamp", "")

    records_info = all_data.get("records_info", {})
    if isinstance(records_info, dict):
        for r_type, records in records_info.items():  # noqa: E501
            for record in records:
                writer.writerow(
                    [
                        domain,
                        timestamp,
                        r_type,
                        record.get("value"),
                        record.get("ttl"),
                        record.get("priority", ""),
                    ]
                )  # noqa: E501

    # Using builtins.print to send to stdout for redirection.
    builtins.print(output_io.getvalue().strip())
