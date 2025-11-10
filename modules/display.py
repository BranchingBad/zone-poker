#!/usr/bin/env python3
"""
Zone-poker - Display Module
Contains all functions for rendering rich output to the console.
"""
from typing import Dict, List, Any
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich import box
from rich.text import Text

# Import shared config and utilities
from .config import console, RECORD_TYPES

# --- All your display functions go here ---
# (display_technology_info, display_dns_records_table,
# display_ptr_table, display_axfr_results, display_email_security,
# display_whois_info, display_nameserver_analysis,
# display_propagation, display_security_audit,
# display_osint_results, display_summary)

# Example:
def display_dns_records_table(records: Dict[str, List[Any]], quiet: bool):
    """Display DNS records in a beautiful table"""
    if quiet:
        return
    
    table = Table(
        title="DNS Records Discovery",
        box=box.ROUNDED,
        show_header=True,
        header_style=None
    )
    
    table.add_column("Type", width=10)
    table.add_column("Value", max_width=50)
    table.add_column("TTL", width=8)
    table.add_column("Extra", width=20)
    
    total_records = 0
    for rtype in RECORD_TYPES:
        record_list = records.get(rtype, [])
        if record_list:
            for idx, record in enumerate(record_list):
                total_records += 1
                value = record.get("value", "")
                ttl = str(record.get("ttl", "N/A"))
                
                extra = ""
                if rtype == "MX" and "priority" in record:
                    extra = f"Priority: {record['priority']}"
                elif rtype == "SRV":
                    extra = f"P:{record.get('priority')} W:{record.get('weight')} Port:{record.get('port')}"
                
                type_display = rtype if idx == 0 else ""
                
                if len(value) > 50:
                    value = value[:47] + "..."
                
                table.add_row(type_display, value, ttl, extra)            
    
    if total_records == 0:
        table.add_row("No records found", "", "", "")
    
    console.print()  # Use the imported console
    console.print(table)
    console.print(f"Total: {total_records} DNS records found\n")

# ...
# ... (Copy ALL other display functions here)
# ... (display_technology_info, display_ptr_table, etc.)
# ...