#!/usr/bin/env python3
"""
Zone-poker - Export Module
"""
import json # Keep for JSON file export
import importlib
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

# Import shared config and utilities
from .config import console
from .utils import get_desktop_path
# Import the dispatch table as the single source of truth
from .dispatch_table import MODULE_DISPATCH_TABLE
from .display import export_txt_summary, export_txt_critical_findings

def export_reports(all_data: Dict[str, Any]):
    """
    Handles all file-based report generation (JSON, TXT, HTML, etc.) by
    dynamically loading the appropriate output module based on file extension.
    """
    args = all_data.get('args_namespace')
    if not args:
        return

    # Determine which file paths were provided by the user
    output_files = []
    if getattr(args, 'export', False):
        output_files.extend(['.json', '.txt']) # Default export types
    if getattr(args, 'html_file', None):
        output_files.append(args.html_file)

    if not output_files:
        return

    # Determine the save directory
    output_dir_str = getattr(args, 'output_dir', None)
    save_path = Path(output_dir_str) if output_dir_str and Path(output_dir_str).is_dir() else get_desktop_path()

    # Generate a base filename from the template
    domain = all_data.get("domain", "report")
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename_template = getattr(args, 'filename_template', '{domain}_dnsint_{timestamp}')
    base_filename = filename_template.format(domain=domain, timestamp=timestamp)

    for file_type in set(output_files): # Use set to avoid duplicates
        # Determine the final file path
        if file_type.startswith('.'): # For default exports like .json, .txt
            filepath = save_path / f"{base_filename}{file_type}"
            output_format = file_type.strip('.')
        else: # For explicitly named files like --html-file report.html
            filepath = Path(file_type)
            output_format = filepath.suffix.strip('.')

        # Add the final filepath to the context for the output module to use
        all_data['export_filepath'] = str(filepath)

        try:
            # Dynamically load the output module (e.g., modules.output.json)
            output_module = importlib.import_module(f".output.{output_format}", package="modules")
            # Call the 'output' function within that module
            output_module.output(all_data)
            console.print(f"[green]✓ {output_format.upper()} report saved to:[/] {filepath}")
        except ImportError:
            console.print(f"[bold red]Error: Export format '{output_format}' is not supported.[/bold red]")
        except Exception as e:
            console.print(f"[bold red]An error occurred while generating the '{output_format}' report: {e}[/bold red]")

def handle_output(all_data: Dict[str, Any], output_format: str):
    """
    Handles dynamic output generation for both the console and file-based reports
    like HTML. It loads the appropriate module from the `modules.output` package.
    """
    args = all_data.get("args_namespace")

    # --- 1. Handle Console Output (non-table formats) ---
    if output_format != 'table':
        # This part remains the same, for printing JSON, XML, etc., to stdout
        # We remove the file-writing responsibility from these modules.
        # Their only job is to print to the console.
        try:
            output_module = importlib.import_module(f".output.{output_format}", package="modules")
            output_module.output(all_data)
        except ImportError:
            console.print(f"[bold red]Error: Console output format '{output_format}' is not supported.[/bold red]")
        except Exception as e:
            console.print(f"[bold red]An error occurred generating '{output_format}' console output: {e}[/bold red]")

    # --- 2. Handle All File Exports ---
    # This is now the single point of entry for creating report files.
    if getattr(args, 'export', False) or getattr(args, 'html_file', None):
        export_reports(all_data)