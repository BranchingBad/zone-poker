#!/usr/bin/env python3
"""
Zone-Poker - Display Utilities
Contains shared decorators and helper functions for console output.
"""
from functools import wraps
from typing import Callable
from typing import Optional
from rich import box
from rich.panel import Panel


def console_display_handler(title: str):
    """
    A decorator to handle common boilerplate for console display functions.
    - Checks for `quiet` mode or empty data.
    - Handles and displays a standardized error panel if `data['error']` exists.
    - Prints a newline after the content is displayed.
    """

    def decorator(func: Callable):
        @wraps(func)
        def wrapper(data: dict, quiet: bool, *args, **kwargs) -> Optional[Panel]:
            if quiet or not data or not isinstance(data, dict):
                return None

            if error := data.get("error"):
                # Return an error panel instead of printing it
                return Panel(
                    f"[dim]{error}[/dim]",
                    title=f"{title} - Error",
                    box=box.ROUNDED,
                    border_style="dim",
                )

            # Call the original display function (e.g., display_dns_records_table)
            # It now returns a rich object (Table, Panel, etc.)
            renderable = func(data, quiet, *args, **kwargs)
            # Return the renderable object to the caller
            return renderable  # type: ignore

        return wrapper

    return decorator
