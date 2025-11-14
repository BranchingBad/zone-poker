#!/usr/bin/env python3
"""
Zone-Poker - JSON Output Module
"""

import json
from typing import Any, Dict, Optional

from ._base import get_export_data, write_output


def output(all_data: Dict[str, Any], output_path: Optional[str] = None):
    """
    Generates and prints a clean JSON report to standard output or a file.
    """
    export_data = get_export_data(all_data)

    # Pretty print the JSON
    json_string = json.dumps(export_data, indent=2, default=str)

    write_output(json_string, output_path, "JSON")
