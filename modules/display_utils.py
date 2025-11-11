#!/usr/bin/env python3
"""
Zone-Poker - Display Utilities
Contains shared decorators and helper functions for console output.
"""
from functools import wraps
from typing import Callable

from rich import box
from rich.panel import Panel

from .config import console


def console_display_handler(title: str):
    """
    A decorator to handle common boilerplate for console display functions.
    - Checks for `quiet` mode or empty data.
    - Handles and displays a standardized error panel if `data['error']` exists.
    - Prints a newline after the content is displayed.
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(data: dict, quiet: bool, output_format: str = 'table', *args, **kwargs):
            if quiet or not data or not isinstance(data, dict):
                return

            if error := data.get("error"):
                console.print(Panel(f"[dim]{error}[/dim]", title=title, box=box.ROUNDED, border_style="dim"),)
                return

            if output_format == 'json':
                import json
                console.print(json.dumps(data, indent=2, default=str))
            elif output_format == 'csv':
                import csv
                import io

                # Handle simple cases: list of dicts
                if isinstance(data, list) and all(isinstance(item, dict) for item in data):
                    if not data:
                        return
                    output = io.StringIO()
                    writer = csv.DictWriter(output, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)
                    console.print(output.getvalue())
                # Handle dict of dicts
                elif isinstance(data, dict) and all(isinstance(item, dict) for item in data.values()):
                    if not data:
                        return
                    # We can assume the keys of the inner dicts are the same
                    first_key = list(data.keys())[0]
                    fieldnames = ['key'] + list(data[first_key].keys())
                    
                    output = io.StringIO()
                    writer = csv.DictWriter(output, fieldnames=fieldnames)
                    writer.writeheader()
                    for key, row_data in data.items():
                        row = {'key': key}
                        row.update(row_data)
                        writer.writerow(row)
                    console.print(output.getvalue())
                else:
                    console.print(f"CSV output not supported for this data structure: {title}")

            else: # table format
                func(data, quiet, *args, **kwargs)
            
            console.print()
        return wrapper
    return decorator