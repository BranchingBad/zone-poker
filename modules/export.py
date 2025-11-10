#!/usr/bin/env python3
"""
Zone-poker - Export Module
Contains functions for exporting reports to files.
"""
import json
from datetime import datetime
from typing import Dict, Any

# Import shared config and utilities
from .config import console
from .utils import get_desktop_path

def export_reports(domain: str, all_data: Dict):
    """Export JSON and TXT reports with enhanced AXFR details to Desktop"""
    desktop_path = get_desktop_path()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    json_file = desktop_path / f"{domain}_dnsint_{timestamp}.json"
    txt_file = desktop_path / f"{domain}_dnsint_{timestamp}.txt"
    
    all_data["export_timestamp"] = datetime.now().isoformat()
    all_data["export_location"] = str(desktop_path)
    
    with open(json_file, "w") as f:
        json.dump(all_data, f, indent=2, default=str)
    
    # Generate a comprehensive TXT report
    with open(txt_file, "w") as f:
        f.write(f"DNS Intelligence Report for: {domain}\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")

        if all_data.get("records"):
            f.write("--- DNS Records ---\n")
            for r_type, items in all_data["records"].items():
                if items:
                    f.write(f"\n{r_type}:\n")
                    for item in items:
                        f.write(f"  - {item.get('value', 'N/A')}\n")
            f.write("\n")

        if all_data.get("whois"):
            f.write("--- WHOIS Information ---\n")
            for key, value in all_data["whois"].items():
                if value:
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            f.write("\n")

        if all_data.get("email_security"):
            f.write("--- Email Security ---\n")
            for key, data in all_data["email_security"].items():
                f.write(f"\n{key.upper()}:\n")
                if isinstance(data, dict):
                    for sub_key, sub_value in data.items():
                        f.write(f"  - {sub_key}: {sub_value}\n")
                else:
                    f.write(f"  - {data}\n")
            f.write("\n")

        if all_data.get("technology"):
            f.write("--- Technology Detection ---\n")
            tech = all_data["technology"]
            if tech.get("technologies"):
                f.write(f"Technologies: {', '.join(tech['technologies'])}\n")
            if tech.get("server"):
                f.write(f"Server: {tech['server']}\n")
            if tech.get("headers"):
                f.write("\nSecurity Headers:\n")
                for h_key, h_value in tech["headers"].items():
                    f.write(f"  - {h_key}: {h_value}\n")

    console.print(f"\n✓ Reports exported to Desktop:")
    console.print(f"  → {json_file}")
    console.print(f"  → {txt_file}\n")