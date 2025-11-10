#!/usr/bin/env python3
"""
Zone-poker - Display Module
Contains all functions for rendering rich output to the console
and formatting text for reports.
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

def display_ptr_lookups(ptr_records: Dict[str, str], quiet: bool):
    """Displays PTR records in a table."""
    if quiet or not ptr_records:
        return

    table = Table(
        title="Reverse DNS (PTR) Lookups",
        box=box.ROUNDED,
        show_header=True,
        header_style=None
    )
    table.add_column("IP Address", width=20)
    table.add_column("Hostname", max_width=60)

    for ip, hostname in ptr_records.items():
        table.add_row(ip, hostname)

    console.print(table)
    console.print(f"Total: {len(ptr_records)} PTR lookups performed\n")

# ...
# ... (All your other display functions like display_whois_info, etc.)
# ...
def display_axfr_results(data: dict, quiet: bool): pass
def display_email_security(data: dict, quiet: bool): pass
def display_whois_info(data: dict, quiet: bool): pass
def display_nameserver_analysis(data: dict, quiet: bool): pass
def display_propagation(data: dict, quiet: bool): pass
def display_security_audit(data: dict, quiet: bool): pass
def display_technology_info(data: dict, quiet: bool): pass
def display_osint_results(data: dict, quiet: bool): pass
def display_summary(data: dict, quiet: bool): pass


# -----------------------------------------------------------------
# --- TXT REPORT EXPORT FUNCTIONS ---
# -----------------------------------------------------------------
# These functions are called by the export module to format
# data for the .txt report.
# -----------------------------------------------------------------

def export_txt_records(data: Dict[str, List[Any]]) -> str:
    """Formats DNS records for the text report."""
    report = ["--- DNS Records ---"]
    total_records = 0
    for r_type, items in data.items():
        if items:
            report.append(f"\n{r_type}:")
            for record in items:
                total_records += 1
                value = record.get("value", "N/A")
                extra = ""
                if r_type == "MX" and "priority" in record:
                    extra = f" (Priority: {record['priority']})"
                elif r_type == "SRV":
                    extra = f" (P: {record.get('priority')} W: {record.get('weight')} Port: {record.get('port')})"
                report.append(f"  - {value}{extra}")
    if total_records == 0:
        report.append("No DNS records found.")
    report.append("\n")
    return "\n".join(report)

def export_txt_ptr(data: Dict[str, str]) -> str:
    """Formats PTR lookups for the text report."""
    report = ["--- Reverse DNS (PTR) Lookups ---"]
    if not data:
        report.append("No PTR records found.")
    for ip, hostname in data.items():
        report.append(f"  - {ip} -> {hostname}")
    report.append("\n")
    return "\n".join(report)

def export_txt_zone(data: Dict[str, Any]) -> str:
    """Formats Zone Transfer results for the text report."""
    report = ["--- Zone Transfer (AXFR) ---"]
    report.append(f"Overall Status: {data.get('summary', data.get('status', 'No data.'))}")
    for server, info in data.get('servers', {}).items():
        report.append(f"  - {server}: {info['status']}")
        if info['status'] == 'Successful':
            report.append(f"    Record Count: {info['record_count']}")
    report.append("\n")
    return "\n".join(report)

def export_txt_mail(data: Dict[str, Any]) -> str:
    """Formats Email Security analysis for the text report."""
    report = ["--- Email Security ---"]
    for key, value in data.items():
        report.append(f"\n{key.upper()}:")
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                report.append(f"  - {sub_key}: {sub_value}")
        else:
            report.append(f"  - {value}")
    report.append("\n")
    return "\n".join(report)

def export_txt_whois(data: Dict[str, Any]) -> str:
    """Formats WHOIS information for the text report."""
    report = ["--- WHOIS Information ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
    for key, value in data.items():
        if value and key != "error":
            report.append(f"{key.replace('_', ' ').title()}: {value}")
    report.append("\n")
    return "\n".join(report)

def export_txt_nsinfo(data: Dict[str, Any]) -> str:
    """Formats Nameserver Analysis for the text report."""
    report = ["--- Nameserver Analysis ---"]
    dnssec_status = data.get("dnssec", "Unknown")
    for ns, info in data.items():
        if ns == "dnssec": continue
        ip = info.get('ip', 'N/A')
        asn = info.get('asn_description', 'N/A')
        report.append(f"  - {ns}")
        report.append(f"    IP: {ip}")
        report.append(f"    ASN: {asn}")
    report.append(f"\nDNSSEC: {dnssec_status}")
    report.append("\n")
    return "\n".join(report)

def export_txt_propagation(data: Dict[str, str]) -> str:
    """Formats DNS Propagation check for the text report."""
    report = ["--- DNS Propagation Check ---"]
    for server, ip in data.items():
        report.append(f"  - {server} ({ip}): {data.get(server, 'N/A')}")
    report.append("\n")
    return "\n".join(report)

def export_txt_security(data: Dict[str, str]) -> str:
    """Formats Security Audit for the text report."""
    report = ["--- Security Audit ---"]
    for check, result in data.items():
        report.append(f"  - {check}: {result}")
    report.append("\n")
    return "\n".join(report)

def export_txt_tech(data: Dict[str, Any]) -> str:
    """Formats Technology Detection for the text report."""
    report = ["--- Technology Detection ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
        return "\n".join(report)
        
    if data.get("technologies"):
        report.append(f"Technologies: {', '.join(data['technologies'])}")
    if data.get("server"):
        report.append(f"Server: {data['server']}")
    if data.get("headers"):
        report.append("\nSecurity Headers:")
        for h_key, h_value in data["headers"].items():
            report.append(f"  - {h_key}: {h_value}")
    report.append("\n")
    return "\n".join(report)

def export_txt_osint(data: Dict[str, Any]) -> str:
    """Formats OSINT Enrichment for the text report."""
    report = ["--- OSINT Enrichment ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
    
    subdomains = data.get('subdomains', [])
    if subdomains:
        report.append("\nSubdomains:")
        for item in subdomains:
            report.append(f"  - {item}")

    passive_dns = data.get('passive_dns', [])
    if passive_dns:
        report.append("\nPassive DNS:")
        for item in passive_dns:
            report.append(f"  - {item.get('hostname')} -> {item.get('ip')} (Last: {item.get('last_seen')})")

    report.append("\n")
    return "\n".join(report)