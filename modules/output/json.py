#!/usr/bin/env python3
"""
Zone-Poker - JSON Output Module
"""
import builtins
import json
from typing import Dict, Any

from modules.dispatch_table import MODULE_DISPATCH_TABLE


def output(all_data: Dict[str, Any]):
    """
    Generates and prints a clean JSON report to standard output.
    """
    export_data = {
        "domain": all_data.get("domain"),
        "scan_timestamp": all_data.get("scan_timestamp"),
    }

    # Add data from each module, using the data_key from the dispatch table
    for module_name, config in MODULE_DISPATCH_TABLE.items():
        data_key = config["data_key"]
        # Only add data if it exists and is not empty
        if data_key in all_data and all_data[data_key]:
            export_data[data_key] = all_data[data_key]

    # Using builtins.print to send to stdout for redirection.
    builtins.print(json.dumps(export_data, indent=2, default=str))