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
        def wrapper(data: dict, quiet: bool, *args, **kwargs):
            if quiet or not data or not isinstance(data, dict):
                return

            if error := data.get("error"):
                console.print(Panel(f"[dim]{error}[/dim]", title=title, box=box.ROUNDED, border_style="dim"),)
            else:
                func(data, quiet, *args, **kwargs)
            console.print()
        return wrapper
    return decorator