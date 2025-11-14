#!/usr/bin/env python3
"""
Zone-Poker - Base Output Module
Contains shared utilities for machine-readable output formats.
"""

import builtins
from typing import Any, Dict, Optional

from modules.dispatch_table import MODULE_DISPATCH_TABLE

from ..config import console


def get_export_data(all_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filters the main data dictionary to create a clean dictionary for export.
    It includes only modules that ran successfully and produced results.
    """
    export_data = {
        "domain": all_data.get("domain"),
        "scan_timestamp": all_data.get("scan_timestamp"),
    }

    for _, config in MODULE_DISPATCH_TABLE.items():
        data_key = config["data_key"]
        module_data = all_data.get(data_key)
        if module_data and not module_data.get("error"):
            export_data[data_key] = module_data

    return export_data


def write_output(content: str, output_path: Optional[str], file_type: str):
    """Writes the provided content to a file or prints it to the console."""
    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
        except IOError as e:
            console.print(f"[bold red]Error writing {file_type.upper()} file to {output_path}: {e}[/bold red]")
    else:
        builtins.print(content)
