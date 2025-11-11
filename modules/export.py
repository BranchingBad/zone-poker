#!/usr/bin/env python3
"""
Zone-poker - Export Module
Contains functions for exporting reports to files.
"""
import json
import io
import csv
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

# Import shared config and utilities
from .config import console
from .utils import get_desktop_path
# Import the dispatch table as the single source of truth
from .dispatch_table import MODULE_DISPATCH_TABLE
from .display import export_txt_summary, export_txt_critical_findings

def export_reports(domain: str, all_data: Dict[str, Any], csv_output: str = None, json_output: str = None):
    """
    Export JSON, TXT, CSV reports to the specified files or Desktop.
    
    The TXT report is generated dynamically by looping through the
    MODULE_DISPATCH_TABLE and calling each module's 'export_func'.
    """
    args = all_data.get('args_namespace')
    output_path_str = getattr(args, 'output_dir', None) if args else None
    save_path: Path

    if output_path_str:
        save_path = Path(output_path_str)
        if not save_path.exists() or not save_path.is_dir():
            console.print(f"[bold red]Error: Output directory '{output_path_str}' not found. Defaulting to Desktop.[/bold red]")
            save_path = get_desktop_path()
    else:
        save_path = get_desktop_path()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # --- JSON Export (Cleaned) ---
    export_data = {
        "domain": all_data.get("domain"),
        "scan_timestamp": all_data.get("scan_timestamp"),
        "export_timestamp": datetime.now().isoformat(),
    }

    # Add data from each module, using the data_key from the dispatch table
    for module_name, config in MODULE_DISPATCH_TABLE.items():
        data_key = config["data_key"]
        # Only add data if it exists and is not empty
        if data_key in all_data and all_data[data_key]:
            export_data[data_key] = all_data[data_key]
    
    exported_files = []

    # Export to JSON file
    if json_output:
        json_file = Path(json_output)
    else:
        json_file = save_path / f"{domain}_dnsint_{timestamp}.json"
    
    with open(json_file, "w") as f:
        json.dump(export_data, f, indent=2, default=str)
    exported_files.append(str(json_file))

    # Export to CSV file
    if csv_output:
        csv_file = Path(csv_output)
        with open(csv_file, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['module', 'key', 'value'])
            for module_name, config in MODULE_DISPATCH_TABLE.items():
                data_key = config["data_key"]
                if data_key in all_data and all_data[data_key]:
                    data = all_data[data_key]
                    if isinstance(data, dict):
                        for key, value in data.items():
                            writer.writerow([data_key, key, str(value)])
                    elif isinstance(data, list):
                        for item in data:
                            writer.writerow([data_key, '', str(item)])
                    else:
                        writer.writerow([data_key, '', str(data)])
        exported_files.append(str(csv_file))

    # --- TXT Report Generation ---
    txt_file = save_path / f"{domain}_dnsint_{timestamp}.txt"
    report_content = []
    report_content.append(f"DNS Intelligence Report for: {domain}")
    report_content.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_content.append("="*50)

    # Add the critical findings section to the top
    critical_string = export_txt_critical_findings(all_data)
    if critical_string:
        report_content.append(critical_string + "\n")

    # --- THIS IS THE FIX: Add the summary section to the top ---
    summary_string = export_txt_summary(all_data)
    report_content.append(summary_string + "\n")

    # Loop through the dispatch table to build the report
    # This ensures the report follows the same order as the scan
    for module_name, config in MODULE_DISPATCH_TABLE.items():
        data_key = config["data_key"]
        export_func = config.get("export_func") # Get the export function
        
        data = all_data.get(data_key)
        
        # If we have data for this key and an export function exists
        if data and export_func:
            try:
                # Call the module's specific export function
                report_string = export_func(data)
                report_content.append(report_string + "\n") # Add newline after each section
            except Exception as e:
                console.print(f"[bold red]Error generating report for {module_name}: {e}[/bold red]")
                report_content.append(f"--- Error exporting {module_name} data ---")

    # Write the combined report string to the file
    with open(txt_file, "w") as f:
        f.write("\n".join(report_content))
    exported_files.append(str(txt_file))

    console.print(f"\n✓ Reports exported to:")
    for file_path in exported_files:
        console.print(f"  → {file_path}")
    console.print("")



def handle_output(all_data: Dict[str, Any], output_format: str, csv_output: str = None, json_output: str = None):
    """
    Handles the output of the scan data in the specified format.
    """
    if output_format == 'json':
        # Prepare data for JSON output, similar to file export
        export_data = {
            "domain": all_data.get("domain"),
            "scan_timestamp": all_data.get("scan_timestamp"),
        }
        for module_name, config in MODULE_DISPATCH_TABLE.items():
            data_key = config["data_key"]
            if data_key in all_data and all_data[data_key]:
                export_data[data_key] = all_data[data_key]
        
        console.print(json.dumps(export_data, indent=2, default=str))
        if json_output:
            export_reports(all_data['domain'], all_data, json_output=json_output)

    elif output_format == 'csv':
        # For CSV, we'll create a simple key-value representation.
        # This is a simplistic approach and might need refinement for complex nested data.
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['module', 'key', 'value'])

        for module_name, config in MODULE_DISPATCH_TABLE.items():
            data_key = config["data_key"]
            if data_key in all_data and all_data[data_key]:
                data = all_data[data_key]
                if isinstance(data, dict):
                    for key, value in data.items():
                        writer.writerow([data_key, key, str(value)])
                elif isinstance(data, list):
                    for item in data:
                        writer.writerow([data_key, '', str(item)])
                else:
                    writer.writerow([data_key, '', str(data)])
        
        console.print(output.getvalue())
        if csv_output:
            export_reports(all_data['domain'], all_data, csv_output=csv_output)