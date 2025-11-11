#!/usr/bin/env python3
"""
Zone-Poker - JSON Output Module
"""
import json
from typing import Dict, Any

from ..config import console
from ..dispatch_table import MODULE_DISPATCH_TABLE

def output(all_data: Dict[str, Any]):
    """
    Prints the scan data to the console in JSON format.
    """
    export_data = {
        "domain": all_data.get("domain"),
        "scan_timestamp": all_data.get("scan_timestamp"),
    }
    for module_name, config in MODULE_DISPATCH_TABLE.items():
        data_key = config["data_key"]
        if data_key in all_data and all_data[data_key]:
            export_data[data_key] = all_data[data_key]
    
    console.print(json.dumps(export_data, indent=2, default=str))