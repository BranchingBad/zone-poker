#!/usr/bin/env python3
"""
Zone-Poker - JSON Output Module
"""
import json
from datetime import datetime
from typing import Dict, Any
from ..dispatch_table import MODULE_DISPATCH_TABLE

def output(all_data: Dict[str, Any]):
    """
    Generates and saves a JSON report.
    The file path is expected to be in all_data['export_filepath'].
    """
    filepath = all_data.get("export_filepath")
    if not filepath:
        # If no filepath, print to console as a fallback
        print(json.dumps(all_data, indent=2, default=str))
        return

    export_data = {
        "domain": all_data.get("domain"),
        "scan_timestamp": all_data.get("scan_timestamp"),
    }

    # Add data from each module, using the data_key from the dispatch table
    for config in MODULE_DISPATCH_TABLE.values():
        data_key = config["data_key"]
        if data := all_data.get(data_key):
            export_data[data_key] = data

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, default=str)