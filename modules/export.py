#!/usr/bin/env python3
"""
Zone-poker - Export Module
"""
from __future__ import annotations
import importlib
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

from .config import console
from .dispatch_table import MODULE_DISPATCH_TABLE
from .utils import get_desktop_path


def export_reports(all_data: Dict[str, Any]):
    """
    Handles all file-based report generation (JSON, TXT, HTML, etc.) by
    dynamically loading the appropriate output module based on file extension.
    """
    args = all_data.get("args_namespace")
    domain = all_data.get("domain", "report")

    # --- TXT Report Generation ---
    if getattr(args, "export", False):
        # Local import from the new module
        from .export_txt import export_txt_summary, export_txt_critical_findings

        report_content = [
            f"Zone-Poker Report for: {domain}\n",
            f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
        ]
        report_content.append(export_txt_critical_findings(all_data))
        report_content.append(export_txt_summary(all_data))

        for module_name, details in MODULE_DISPATCH_TABLE.items():
            is_module_requested = getattr(args, module_name, False)
            is_all_requested = getattr(args, "all", False)
            if is_module_requested or is_all_requested:
                if export_func := details.get("export_func"):
                    module_data = all_data.get(details["data_key"], {})
                    report_content.append(export_func(module_data))

        all_data["txt_report_content"] = "\n\n".join(report_content)

    if not args:
        return

    # Determine which file paths were provided by the user
    output_files = []
    if getattr(args, "export", False):
        output_files.extend([".json", ".txt"])  # Default export types
    if html_file := getattr(args, "html_file", None):
        output_files.append(html_file)

    if not output_files:
        return

    # Determine the save directory
    output_dir_str = getattr(args, "output_dir", None)
    if output_dir_str and Path(output_dir_str).is_dir():
        save_path = Path(output_dir_str)
    else:
        save_path = get_desktop_path()

    # Generate a base filename from the template
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_template = getattr(
        args, "filename_template", "{domain}_dnsint_{timestamp}"
    )
    base_filename = filename_template.format(domain=domain, timestamp=timestamp)

    for file_type in set(output_files):  # Use set to avoid duplicates
        # Determine the final file path
        if file_type.startswith("."):  # For default exports like .json, .txt
            filepath = save_path / f"{base_filename}{file_type}"
            output_format = file_type.strip(".")
        else:  # For explicitly named files like --html-file report.html
            filepath = Path(file_type)
            output_format = filepath.suffix.strip(".")
        # Add the final filepath to the context for the output module to use
        all_data["export_filepath"] = str(filepath)

        try:
            # Dynamically load the output module (e.g., modules.output.json)
            output_module = importlib.import_module(
                f".output.{output_format}", package="modules"
            )
            # Call the 'output' function within that module  # noqa: E501
            output_module.output(all_data)
        except ImportError:
            console.print(
                f"[bold red]Error: Export format '{output_format}' is not "
                "supported.[/bold red]"
            )
        except Exception as e:
            console.print(
                f"[bold red]An error occurred while generating the "
                f"'{output_format}' report: {e}[/bold red]"
            )


def handle_output(all_data: Dict[str, Any], mode: str):
    """
    Handles dynamic output generation for both the console and file-based reports
    like HTML. It loads the appropriate module from the `modules.output` package.

    Args:
        all_data: The dictionary containing all scan data.
        mode: The output mode. Can be 'file' for file exports or a specific
              format like 'json', 'csv' for console output.
    """
    args = all_data.get("args_namespace")

    # --- 1. Handle File Exports ---
    if mode == "file":
        if getattr(args, "export", False) or getattr(args, "html_file", None):
            export_reports(all_data)
    # --- 2. Handle Console Output (non-table formats) ---
    elif mode != "table":
        try:
            output_module = importlib.import_module(
                f".output.{mode}", package="modules"
            )
            output_module.output(all_data)
        except ImportError:
            console.print(
                f"[bold red]Error: Console output format '{mode}' is not "
                "supported.[/bold red]"
            )
        except Exception as e:
            console.print(
                f"[bold red]An error occurred generating '{mode}' console output: "
                f"{e}[/bold red]"
            )
