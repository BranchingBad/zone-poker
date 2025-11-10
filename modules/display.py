#!/usr/bin/env python3
"""
Zone-poker - Display Module
Contains all functions for rendering rich output to the console
and formatting text for reports.
"""
import datetime
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
    if quiet or not records:
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
    
    console.print()
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

def display_axfr_results(data: dict, quiet: bool):
    """Displays Zone Transfer (AXFR) results in a tree."""
    if quiet or not data:
        return

    summary = data.get('summary', data.get('status', 'No data.'))
    style = "bold red" if "Vulnerable" in summary else "bold green"
    
    tree = Tree(f"[bold]Zone Transfer (AXFR): [/bold][{style}]{summary}[/{style}]")
    
    servers = data.get('servers', {})
    if not servers:
        tree.add("[dim]No nameservers were checked.[/dim]")
    
    for server, info in servers.items():
        status = info.get('status', 'Unknown')
        if status == 'Successful':
            node = tree.add(f"✓ [green]{server}: {status} ({info.get('record_count', 0)} records)[/green]")
        elif "Refused" in status:
            node = tree.add(f"✗ [yellow]{server}: {status}[/yellow]")
        else:
            node = tree.add(f"✗ [dim]{server}: {status}[/dim]")

    console.print(tree)
    console.print()

def display_email_security(data: dict, quiet: bool):
    """Displays Email Security results in a table."""
    if quiet or not data:
        return

    table = Table(title="Email Security Analysis", box=box.ROUNDED, show_header=False, header_style=None)
    table.add_column("Check", style="bold cyan", width=10)
    table.add_column("Result")

    # SPF
    spf_data = data.get("spf", {})
    if spf_data.get("status") == "Not Found":
        table.add_row("SPF", "[red]Not Found[/red]")
    elif spf_data.get("raw"):
        policy = spf_data.get('all_policy', 'N/A')
        color = "red" if policy == "?all" else "yellow" if policy == "~all" else "green"
        spf_status = f"[{color}]{policy}[/{color}]"
        
        if "warning" in spf_data:
            spf_status += f"\n[yellow]Warning: {spf_data['warning']}[/yellow]"
        table.add_row("SPF", f"{spf_data['raw']}\nPolicy: {spf_status}")

    # DMARC
    dmarc_data = data.get("dmarc", {})
    if dmarc_data.get("status") == "Not Found":
        table.add_row("DMARC", "[red]Not Found[/red]")
    elif dmarc_data.get("raw"):
        policy = dmarc_data.get('p', 'N/A')
        color = "red" if policy == "none" else "green"
        table.add_row("DMARC", f"{dmarc_data['raw']}\nPolicy: [{color}]{policy}[/{color}]")

    # DKIM
    table.add_row("DKIM", data.get("dkim", {}).get("status", "N/A"))
    
    console.print(table)
    console.print()

def display_whois_info(data: dict, quiet: bool):
    """Displays WHOIS data in a rich panel."""
    if quiet or not data:
        return

    # Handle the error case first
    if data.get("error"):
        panel = Panel(f"[bold red]WHOIS Error:[/bold red] {data['error']}", title="WHOIS Information", box=box.ROUNDED, border_style="red")
        console.print(panel)
        console.print()
        return

    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column("Key", style="bold cyan", no_wrap=True, width=18)
    table.add_column("Value")

    key_fields = [
        'domain_name', 'registrar', 'status', 'creation_date', 
        'expiration_date', 'updated_date', 'name_servers', 'emails'
    ]
    
    for key in key_fields:
        if key in data and data[key]:
            value = data[key]
            
            if isinstance(value, list):
                value_str = "\n".join(str(v) for v in value)
            elif 'date' in key and isinstance(value, str):
                try:
                    dt = datetime.datetime.fromisoformat(value)
                    value_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    value_str = str(value) 
            else:
                value_str = str(value)
            
            table.add_row(f"{key.replace('_', ' ').title()}:", value_str)

    console.print(Panel(table, title="WHOIS Information", box=box.ROUNDED, expand=False))
    console.print()

def display_nameserver_analysis(data: dict, quiet: bool):
    """Displays Nameserver Analysis in a table."""
    if quiet or not data:
        return
        
    dnssec_status = data.get("dnssec", "Unknown")
    color = "green" if "Enabled" in dnssec_status else "red"
    title = f"Nameserver Analysis (DNSSEC: [{color}]{dnssec_status}[/{color}])"

    table = Table(title=title, box=box.ROUNDED, show_header=True, header_style=None)
    table.add_column("Nameserver", style="bold")
    table.add_column("IP Address(es)")
    table.add_column("ASN Description")
    
    for ns, info in data.items():
        if ns == "dnssec": 
            continue
        if "error" in info:
            table.add_row(ns, f"[red]{info['error']}[/red]", "")
        else:
            # --- THIS BLOCK IS FIXED ---
            ip_list = info.get('ips', [])
            ip_str = "\n".join(ip_list) if ip_list else "N/A"
            table.add_row(ns, ip_str, info.get('asn_description', 'N/A'))
            
    console.print(table)
    console.print()

def display_propagation(data: dict, quiet: bool):
    """Displays DNS Propagation check results in a table."""
    if quiet or not data:
        return
        
    table = Table(title="DNS Propagation Check", box=box.ROUNDED, show_header=True, header_style=None)
    table.add_column("Resolver", style="bold")
    table.add_column("IP Address")

    ips = set(data.values())
    color_map = {ip: f"color({i+1})" for i, ip in enumerate(ips)}
    
    for server, ip in data.items():
        if "Error" in ip:
            table.add_row(server, f"[red]{ip}[/red]")
        else:
            color = color_map.get(ip, "white")
            table.add_row(server, f"[{color}]{ip}[/{color}]")

    console.print(table)
    console.print()

def display_security_audit(data: dict, quiet: bool):
    """Displays Security Audit results in a table."""
    if quiet or not data:
        return

    table = Table(title="Security Audit", box=box.ROUNDED, show_header=True, header_style=None)
    table.add_column("Check", style="bold")
    table.add_column("Result", max_width=50)

    for check, result in data.items():
        color = "red" if "Weak" in result or "Not Found" in result else "green" if "Secure" in result or "Present" in result else "yellow"
        table.add_row(check, f"[{color}]{result}[/{color}]")

    console.print(table)
    console.print()

def display_technology_info(data: dict, quiet: bool):
    """Displays Technology Detection results in a panel."""
    if quiet or not data:
        return
        
    if data.get("error"):
        panel = Panel(f"[dim]{data['error']}[/dim]", title="Technology Detection", box=box.ROUNDED, border_style="dim")
        console.print(panel)
        console.print()
        return

    tree = Tree(f"[bold]Server:[/bold] {data.get('server', 'N/A')}")
    
    tech = data.get('technologies')
    if tech:
        tech_str = ", ".join(tech)
        tree.add(f"[bold]Technologies:[/bold] {tech_str}")
    
    headers = data.get('headers')
    if headers:
        sec_headers = [
            'strict-transport-security', 'content-security-policy', 
            'x-content-type-options', 'x-frame-options'
        ]
        header_tree = tree.add("[bold]Security Headers:[/bold]")
        for h in sec_headers:
            if h in headers:
                header_tree.add(f"[green]✓ {h}[/green]: {headers[h]}")
            else:
                header_tree.add(f"[red]✗ {h}[/red]: Not Found")

    console.print(Panel(tree, title="Technology Detection", box=box.ROUNDED))
    console.print()

def display_osint_results(data: dict, quiet: bool):
    """Displays OSINT results in a tree."""
    if quiet or not data:
        return
        
    tree = Tree("[bold]OSINT Enrichment[/bold]")
    
    if data.get("error"):
        tree.add(f"[red]Error: {data['error']}[/red]")
        console.print(tree)
        console.print()
        return

    subdomains = data.get('subdomains', [])
    if subdomains:
        sub_tree = tree.add(f"Passive Subdomains ({len(subdomains)} found)")
        for s in subdomains:
            sub_tree.add(f"[green]{s}[/green]")
    else:
        tree.add("[dim]No passive subdomains found.[/dim]")

    passive_dns = data.get('passive_dns', [])
    if passive_dns:
        pdns_tree = tree.add(f"Passive DNS Records ({len(passive_dns)} found)")
        for r in passive_dns:
            pdns_tree.add(f"{r.get('hostname')} -> {r.get('ip')} [dim](Last: {r.get('last_seen')})[/dim]")
    else:
        tree.add("[dim]No passive DNS records found.[/dim]")

    console.print(tree)
    console.print()

def display_summary(data: dict, quiet: bool):
    """Displays a high-level summary of findings."""
    if quiet:
        return
        
    table = Table(title="Scan Summary", box=box.ROUNDED, show_header=False, header_style=None)
    table.add_column("Module", style="bold cyan")
    table.add_column("Finding")
    
    # Zone Transfer
    axfr_summary = data.get('zone_info', {}).get('summary', 'N/A')
    axfr_color = "bold red" if "Vulnerable" in axfr_summary else "green"
    table.add_row("Zone Transfer", f"[{axfr_color}]{axfr_summary}[/{axfr_color}]")
    
    # SPF
    spf_policy = data.get('email_security', {}).get('spf', {}).get('all_policy', 'Not Found')
    spf_color = "red" if spf_policy in ["?all", "Not Found"] else "yellow" if spf_policy == "~all" else "green"
    table.add_row("SPF Policy", f"[{spf_color}]{spf_policy}[/{spf_color}]")
    
    # DMARC
    dmarc_policy = data.get('email_security', {}).get('dmarc', {}).get('p', 'Not Found')
    dmarc_color = "red" if dmarc_policy in ["none", "Not Found"] else "green"
    table.add_row("DMARC Policy", f"[{dmarc_color}]{dmarc_policy}[/{dmarc_color}]")

    # Security Audit
    audit_findings = data.get('security', {})
    weak_findings = [k for k, v in audit_findings.items() if "Weak" in v or "Not Found" in v]
    if weak_findings:
        table.add_row("Security Audit", f"[red]Found {len(weak_findings)} issues[/red] ({', '.join(weak_findings)})")
    else:
        table.add_row("Security Audit", "[green]All checks passed[/green]")

    console.print(table)
    console.print()

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
            # Format lists and dates for text report
            if isinstance(value, list):
                value_str = ", ".join(str(v) for v in value)
            elif 'date' in key and isinstance(value, str):
                try:
                    dt = datetime.datetime.fromisoformat(value)
                    value_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    value_str = str(value)
            else:
                value_str = str(value)
            report.append(f"{key.replace('_', ' ').title()}: {value_str}")
    report.append("\n")
    return "\n".join(report)

def export_txt_nsinfo(data: Dict[str, Any]) -> str:
    """Formats Nameserver Analysis for the text report."""
    report = ["--- Nameserver Analysis ---"]
    dnssec_status = data.get("dnssec", "Unknown")
    for ns, info in data.items():
        if ns == "dnssec": continue
        
        # --- THIS BLOCK IS FIXED ---
        ip_list = info.get('ips', [])
        ip_str = ", ".join(ip_list) if ip_list else "N/A" # Use comma for TXT
        asn = info.get('asn_description', 'N/A')
        report.append(f"  - {ns}")
        report.append(f"    IP(s): {ip_str}")
        report.append(f"    ASN: {asn}")
        
    report.append(f"\nDNSSEC: {dnssec_status}")
    report.append("\n")
    return "\n".join(report)

def export_txt_propagation(data: Dict[str, str]) -> str:
    """Formats DNS Propagation check for the text report."""
    report = ["--- DNS Propagation Check ---"]
    for server, ip in data.items():
        report.append(f"  - {server}: {data.get(server, 'N/A')}")
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
        report.append("\n")
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