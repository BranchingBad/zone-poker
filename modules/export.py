#!/usr/bin/env python3
"""
Zone-Poker - Output Handling Module
"""
import importlib
from typing import Dict, Any, Optional

from .config import console


def handle_output(
    all_data: Dict[str, Any], output_format: str, output_path: Optional[str] = None
):
    """
    Handles dynamic output generation for console and file-based reports.

    Args:
        all_data: The dictionary containing all scan data.
        output_format: The output format (e.g., 'json', 'csv', 'html').
        output_path: Optional file path to save the output. If None, prints to console.
    """
    try:
        # Dynamically load the output module (e.g., modules.output.json)
        output_module = importlib.import_module(
            f".output.{output_format}", package="modules"
        )
        # The output module's `output` function will handle writing to a file
        # if a path is provided, or printing to the console otherwise.
        output_module.output(all_data, output_path)
        if output_path:
            console.print(
                f"[green]✓ Report successfully saved to:[/] [bold cyan]{output_path}[/bold cyan]"
            )
    except ImportError:
        console.print(
            f"[bold red]Error: Output format '{output_format}' is not supported.[/bold red]"
        )
    except Exception as e:
        console.print(
            f"[bold red]An error occurred while generating the '{output_format}' report: {e}[/bold red]"
        )
