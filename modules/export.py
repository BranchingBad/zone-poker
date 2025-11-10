#!/usr/bin/env python3
"""
Zone-poker - Export Module
Contains functions for exporting reports to files.
"""
import json
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

# Import shared config and utilities
from .config import console
from .utils import get_desktop_path
# Import the dispatch table as the single source of truth
from .orchestrator import MODULE_DISPATCH_TABLE

def export_reports(domain: str, all_data: Dict[str, Any]):
    """
    Export JSON and TXT reports to the Desktop.
    
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
    
    json_file = save_path / f"{domain}_dnsint_{timestamp}.json"
    txt_file = save_path / f"{domain}_dnsint_{timestamp}.txt"
    
    # --- JSON Export (Cleaned) ---
    export_data = {
        "domain": all_data.get("domain"),
        "scan_timestamp": all_data.get("scan_timestamp"),
        "export_timestamp": datetime.now().isoformat(),
        "export_location": str(save_path)
    }

    # Add data from each module, using the data_key from the dispatch table
    for module_name, config in MODULE_DISPATCH_TABLE.items():
        data_key = config["data_key"]
        # Only add data if it exists and is not empty
        if data_key in all_data and all_data[data_key]:
            export_data[data_key] = all_data[data_key]
    
    with open(json_file, "w") as f:
        json.dump(export_data, f, indent=2, default=str)
    
    # --- TXT Report Generation ---
    report_content = []
    report_content.append(f"DNS Intelligence Report for: {domain}")
    report_content.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_content.append("="*50 + "\n")

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
                report_content.append(report_string)
            except Exception as e:
                console.print(f"[bold red]Error generating report for {module_name}: {e}[/bold red]")
                report_content.append(f"--- Error exporting {module_name} data ---")

    # Write the combined report string to the file
    with open(txt_file, "w") as f:
        f.write("\n".join(report_content))

    console.print(f"\n✓ Reports exported to {save_path}:")
    console.print(f"  → {json_file}")
    console.print(f"  → {txt_file}\n")