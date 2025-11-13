#!/usr/bin/env python3
"""
Zone-Poker - JSON Output Module
"""
import builtins
import json
from typing import Dict, Any, Optional

from ..config import console
from modules.dispatch_table import MODULE_DISPATCH_TABLE


def output(all_data: Dict[str, Any], output_path: Optional[str] = None):
    """
    Generates and prints a clean JSON report to standard output or a file.

    It selectively includes data from modules that were run and produced results,
    ensuring a clean and relevant output.
    Args:
        all_data: The dictionary containing all scan data.
        output_path: If provided, the output is written to this file path.
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

    # Pretty print the JSON
    json_string = json.dumps(export_data, indent=2, default=str)

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_string)
        except IOError as e:
            console.print(
                f"[bold red]Error writing JSON file to {output_path}: {e}[/bold red]"
            )
    else:
        builtins.print(json_string)
