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
    # This loop is data-driven (from a previous fix)
    for rtype in records.keys():
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
                elif rtype == "SOA":
                    extra = f"Serial: {record.get('serial')}"
                
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
            node = tree.add(f"✓ [green]{server}: {status} ({info.get('record_count', 0)} records via {info.get('ip_used')})[/green]")
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

    # --- THIS SECTION IS REFACTORED ---
    # Iterate over all data items instead of a hardcoded list.
    # Exclude keys that are not helpful in the display.
    EXCLUDE_KEYS = {'error'}
    
    for key, value in data.items():
        if key in EXCLUDE_KEYS or not value:
            continue
            
        # --- THIS IS THE FIX for duplicate WHOIS data ---
        # If the value is a list, take the first element to deduplicate.
        if isinstance(value, list):
            if not value: continue
            value = value[0]

        elif 'date' in key and isinstance(value, str):
            try:
                dt = datetime.datetime.fromisoformat(value)
                value_str = dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                value_str = str(value) 
        else:
            value_str = str(value)
        
        table.add_row(f"{key.replace('_', ' ').title()}:", value_str)
    # --- END REFACTOR ---

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
    
    # --- THIS IS THE FIX: Handle top-level error ---
    if data.get("error"):
        table.add_row("[red]Error[/red]", f"[red]{data['error']}[/red]", "")
        console.print(table)
        console.print()
        return
    for ns, info in data.items():
        if ns == "dnssec": 
            continue
            
        # --- THIS BLOCK IS FIXED ---
        # Check if info is a dictionary before trying to access it.
        # This handles the case where the 'records' module fails and
        # 'nameserver_analysis' returns {"error": "..."}
        if isinstance(info, dict):
            if "error" in info:
                table.add_row(ns, f"[red]{info['error']}[/red]", "")
            else:
                ip_list = info.get('ips', [])
                ip_str = "\n".join(ip_list) if ip_list else "N/A"
                table.add_row(ns, ip_str, info.get('asn_description', 'N/A'))
        elif ns == "error":
            # Handle the top-level error from nameserver_analysis
            table.add_row(f"[red]{ns.title()}[/red]", f"[red]{info}[/red]", "")
            
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

def display_ssl_info(data: dict, quiet: bool):
    """Displays SSL/TLS Certificate analysis in a panel."""
    if quiet or not data:
        return

    if data.get("error"):
        panel = Panel(f"[dim]{data['error']}[/dim]", title="SSL/TLS Certificate Analysis", box=box.ROUNDED, border_style="dim")
        console.print(panel)
        console.print()
        return

    tree = Tree(f"[bold]Subject:[/bold] {data.get('subject', 'N/A')}")
    tree.add(f"[bold]Issuer:[/bold] {data.get('issuer', 'N/A')}")

    # Validity
    valid_from_ts = data.get('valid_from')
    valid_until_ts = data.get('valid_until')
    now = datetime.datetime.now().timestamp()

    if valid_from_ts and valid_until_ts:
        valid_from_dt = datetime.datetime.fromtimestamp(valid_from_ts).strftime('%Y-%m-%d')
        valid_until_dt = datetime.datetime.fromtimestamp(valid_until_ts).strftime('%Y-%m-%d')
        
        if now > valid_until_ts:
            validity_str = f"[red]Expired on {valid_until_dt}[/red]"
        elif now < valid_from_ts:
            validity_str = f"[yellow]Not yet valid (starts {valid_from_dt})[/yellow]"
        else:
            validity_str = f"[green]Valid from {valid_from_dt} to {valid_until_dt}[/green]"
        tree.add(f"[bold]Validity:[/bold] {validity_str}")

    # SANs
    sans = data.get('sans', [])
    if sans:
        sans_tree = tree.add(f"Subject Alternative Names ({len(sans)} found)")
        for s in sans:
            sans_tree.add(f"[green]{s}[/green]")

    # Connection Info
    tree.add(f"[bold]TLS Version:[/bold] {data.get('tls_version', 'N/A')}")

    console.print(Panel(tree, title="SSL/TLS Certificate Analysis", box=box.ROUNDED))
    console.print()

def display_smtp_info(data: dict, quiet: bool):
    """Displays Mail Server (SMTP) analysis in a panel."""
    if quiet or not data:
        return

    if data.get("error"):
        panel = Panel(f"[dim]{data['error']}[/dim]", title="Mail Server (SMTP) Analysis", box=box.ROUNDED, border_style="dim")
        console.print(panel)
        console.print()
        return

    tree = Tree("[bold]SMTP Server Analysis[/bold]")
    for server, info in data.items():
        if info.get("error"):
            tree.add(f"✗ [red]{server}[/red]: {info['error']}")
            continue

        node = tree.add(f"✓ [green]{server}[/green]")
        node.add(f"Banner: [dim]{info.get('banner', 'N/A')}[/dim]")
        
        starttls_status = info.get('starttls', 'Unknown')
        color = "green" if starttls_status == "Supported" else "yellow"
        node.add(f"STARTTLS: [{color}]{starttls_status}[/{color}]")

        cert_info = info.get('certificate')
        if cert_info:
            cert_tree = node.add("[bold]Certificate Info[/bold]")
            cert_tree.add(f"Subject: {cert_info.get('subject', 'N/A')}")
            
            valid_until_ts = cert_info.get('valid_until')
            if valid_until_ts:
                now = datetime.datetime.now().timestamp()
                valid_until_dt = datetime.datetime.fromtimestamp(valid_until_ts).strftime('%Y-%m-%d')
                if now > valid_until_ts:
                    cert_tree.add(f"Validity: [red]Expired on {valid_until_dt}[/red]")
                else:
                    cert_tree.add(f"Validity: [green]Valid until {valid_until_dt}[/green]")

    console.print(Panel(tree, title="Mail Server (SMTP) Analysis", box=box.ROUNDED))
    console.print()

def display_reputation_info(data: dict, quiet: bool):
    """Displays IP Reputation analysis in a panel."""
    if quiet or not data:
        return

    if data.get("error"):
        panel = Panel(f"[dim]{data['error']}[/dim]", title="IP Reputation Analysis (AbuseIPDB)", box=box.ROUNDED, border_style="dim")
        console.print(panel)
        console.print()
        return

    tree = Tree("[bold]IP Reputation Analysis (AbuseIPDB)[/bold]")
    for ip, info in data.items():
        if info.get("error"):
            tree.add(f"✗ [red]{ip}[/red]: {info['error']}")
            continue

        score = info.get('abuseConfidenceScore', 0)
        if score > 50:
            color = "red"
        elif score > 0:
            color = "yellow"
        else:
            color = "green"
        
        node = tree.add(f"✓ [{color}]{ip}[/{color}]")
        node.add(f"Abuse Score: [{color}]{score}[/{color}]")
        node.add(f"Total Reports: {info.get('totalReports', 0)}")
        
        if info.get('lastReportedAt'):
            last_reported = datetime.datetime.fromisoformat(info['lastReportedAt'].replace('Z', '+00:00')).strftime('%Y-%m-%d')
            node.add(f"Last Reported: {last_reported}")

    console.print(Panel(tree, title="IP Reputation Analysis (AbuseIPDB)", box=box.ROUNDED))
    console.print()

def display_content_hash_info(data: dict, quiet: bool):
    """Displays Favicon and Content Hash results in a panel."""
    if quiet or not data:
        return

    if data.get("error"):
        panel = Panel(f"[dim]{data['error']}[/dim]", title="Content & Favicon Hashes", box=box.ROUNDED, border_style="dim")
        console.print(panel)
        console.print()
        return

    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column("Key", style="bold cyan", no_wrap=True, width=25)
    table.add_column("Value")

    if data.get("favicon_murmur32_hash"):
        table.add_row("Favicon Murmur32 Hash:", data["favicon_murmur32_hash"])
    if data.get("page_sha256_hash"):
        table.add_row("Page Content SHA256:", data["page_sha256_hash"])

    console.print(Panel(table, title="Content & Favicon Hashes", box=box.ROUNDED, expand=False))
    console.print()

def display_ct_logs(data: dict, quiet: bool):
    """Displays Certificate Transparency Log results in a tree."""
    if quiet or not data:
        return

    if data.get("error"):
        panel = Panel(f"[dim]{data['error']}[/dim]", title="Certificate Transparency Log Analysis", box=box.ROUNDED, border_style="dim")
        console.print(panel)
        console.print()
        return

    subdomains = data.get('subdomains', [])
    tree = Tree(f"[bold]Certificate Transparency Log Analysis ({len(subdomains)} found)[/bold]")

    if subdomains:
        for s in subdomains:
            tree.add(f"[green]{s}[/green]")
    else:
        tree.add("[dim]No subdomains found in CT logs.[/dim]")

    console.print(tree)
    console.print()

def display_waf_detection(data: dict, quiet: bool):
    """Displays WAF Detection results in a panel."""
    if quiet or not data:
        return

    if data.get("error"):
        panel = Panel(f"[dim]{data['error']}[/dim]", title="WAF Detection", box=box.ROUNDED, border_style="dim")
        console.print(panel)
        console.print()
        return

    detected_waf = data.get("detected_waf", "None")
    if detected_waf != "None":
        color = "green"
        reason = data.get("details", {}).get("reason", "")
        message = f"Identified [bold]{detected_waf}[/bold]. [dim]({reason})[/dim]"
    else:
        color = "dim"
        message = "No WAF identified."
    console.print(Panel(f"[{color}]{message}[/{color}]", title="WAF Detection", box=box.ROUNDED))
    console.print()

def display_dane_analysis(data: dict, quiet: bool):
    """Displays DANE/TLSA analysis in a panel."""
    if quiet or not data:
        return

    if data.get("error"):
        panel = Panel(f"[dim]{data['error']}[/dim]", title="DANE/TLSA Record Analysis", box=box.ROUNDED, border_style="dim")
        console.print(panel)
        console.print()
        return

    status = data.get("status", "Not Found")
    if status == "Present":
        color = "green"
        tree = Tree(f"✓ [{color}]DANE/TLSA records found for _443._tcp (HTTPS)[/{color}]")
        for record in data.get("records", []):
            tree.add(f"[dim]{record}[/dim]")
    else:
        color = "dim"
        tree = Tree(f"[{color}]No DANE/TLSA records found for _443._tcp (HTTPS)[/{color}]")

    console.print(Panel(tree, title="DANE/TLSA Record Analysis", box=box.ROUNDED))
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
                elif r_type == "SOA":
                    extra = f" (Serial: {record.get('serial')})"
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

def export_txt_content_hash(data: Dict[str, Any]) -> str:
    """Formats Content Hash analysis for the text report."""
    report = ["--- Content & Favicon Hashes ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
        report.append("\n")
        return "\n".join(report)

    if data.get("favicon_murmur32_hash"):
        report.append(f"Favicon Murmur32 Hash: {data['favicon_murmur32_hash']}")
    if data.get("page_sha256_hash"):
        report.append(f"Page Content SHA256: {data['page_sha256_hash']}")

    report.append("\n")
    return "\n".join(report)

def export_txt_ct_logs(data: Dict[str, Any]) -> str:
    """Formats CT Log analysis for the text report."""
    report = ["--- Certificate Transparency Log Analysis ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
    
    subdomains = data.get('subdomains', [])
    if subdomains:
        report.append(f"Found {len(subdomains)} subdomains:")
        for item in subdomains:
            report.append(f"  - {item}")
    else:
        report.append("No subdomains found in CT logs.")
    report.append("\n")
    return "\n".join(report)

def export_txt_waf_detection(data: Dict[str, Any]) -> str:
    """Formats WAF Detection analysis for the text report."""
    report = ["--- WAF Detection ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
    else:
        detected_waf = data.get("detected_waf", "None")
        if detected_waf != "None":
            reason = data.get("details", {}).get("reason", "")
            report.append(f"Identified: {detected_waf} (Reason: {reason})")
        else:
            report.append("No WAF identified from response headers.")
    report.append("\n")
    return "\n".join(report)

def display_http_headers(data: dict, quiet: bool):
    """Displays HTTP Security Header analysis in a panel."""
    if quiet or not data:
        return

    if data.get("error"):
        panel = Panel(f"[dim]{data['error']}[/dim]", title="HTTP Security Headers Analysis", box=box.ROUNDED, border_style="dim")
        console.print(panel)
        console.print()
        return

    tree = Tree(f"[bold]HTTP Security Headers Analysis[/bold]\n[dim]Final URL: {data.get('final_url')}[/dim]")

    analysis = data.get("analysis", {})
    for header, info in analysis.items():
        status = info.get("status", "Unknown")
        value = info.get("value", "")

        if status == "Strong" or status == "Present":
            color = "green"
            icon = "✓"
        elif status == "Weak":
            color = "yellow"
            icon = "!"
        else: # Missing or Invalid
            color = "red"
            icon = "✗"

        display_value = f": [dim]{value}[/dim]" if value else ""
        tree.add(f"{icon} [{color}]{header}[/{color}] - {status}{display_value}")

    recommendations = data.get("recommendations", [])
    if recommendations:
        rec_tree = tree.add("[bold cyan]Recommendations[/bold cyan]")
        for rec in recommendations:
            rec_tree.add(f"• {rec}")

    console.print(Panel(tree, title="HTTP Security Headers Analysis", box=box.ROUNDED))
    console.print()

def export_txt_dane(data: Dict[str, Any]) -> str:
    """Formats DANE/TLSA analysis for the text report."""
    report = ["--- DANE/TLSA Record Analysis ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
    else:
        status = data.get("status", "Not Found")
        report.append(f"Status for _443._tcp (HTTPS): {status}")
        records = data.get("records", [])
        if records:
            report.append("\nRecords:")
            for record in records:
                report.append(f"  - {record}")
    report.append("\n")
    return "\n".join(report)

def display_ip_geolocation(data: dict, quiet: bool):
    """Displays IP Geolocation results in a table."""
    if quiet or not data:
        return

    table = Table(title="IP Geolocation", box=box.ROUNDED, show_header=True, header_style=None)
    table.add_column("IP Address", style="bold", width=20)
    table.add_column("Country")
    table.add_column("City")
    table.add_column("ISP")

    for ip, info in data.items():
        if info.get("error"):
            table.add_row(ip, f"[red]{info['error']}[/red]", "", "")
        else:
            table.add_row(
                ip,
                info.get("country", "N/A"),
                info.get("city", "N/A"),
                info.get("isp", "N/A"),
            )
    console.print(table)
    console.print()

def export_txt_ssl(data: Dict[str, Any]) -> str:
    """Formats SSL/TLS analysis for the text report."""
    report = ["--- SSL/TLS Certificate Analysis ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
        report.append("\n")
        return "\n".join(report)

    report.append(f"Subject: {data.get('subject', 'N/A')}")
    report.append(f"Issuer: {data.get('issuer', 'N/A')}")

    valid_from_ts = data.get('valid_from')
    if valid_from_ts:
        report.append(f"Valid From: {datetime.datetime.fromtimestamp(valid_from_ts).strftime('%Y-%m-%d %H:%M:%S')}")
    valid_until_ts = data.get('valid_until')
    if valid_until_ts:
        report.append(f"Valid Until: {datetime.datetime.fromtimestamp(valid_until_ts).strftime('%Y-%m-%d %H:%M:%S')}")

    if data.get('sans'):
        report.append("\nSubject Alternative Names:")
        for s in data['sans']:
            report.append(f"  - {s}")
    report.append("\n")
    return "\n".join(report)

def export_txt_geolocation(data: Dict[str, Any]) -> str:
    """Formats IP Geolocation for the text report."""
    report = ["--- IP Geolocation ---"]
    if not data:
        report.append("No IP addresses were geolocated.")
    for ip, info in data.items():
        if info.get("error"):
            report.append(f"  - {ip}: Error - {info['error']}")
        else:
            country = info.get('country', 'N/A')
            city = info.get('city', 'N/A')
            isp = info.get('isp', 'N/A')
            report.append(f"  - {ip}: {city}, {country} (ISP: {isp})")
    report.append("\n")
    return "\n".join(report)

def export_txt_http_headers(data: Dict[str, Any]) -> str:
    """Formats HTTP Security Headers for the text report."""
    report = ["--- HTTP Security Headers Analysis ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
    else:
        report.append(f"Final URL: {data.get('final_url')}\n")
        analysis = data.get("analysis", {})
        for header, info in analysis.items():
            status = info.get("status", "Unknown")
            value = info.get("value", "")
            value_str = f" - Value: {value}" if value else ""
            report.append(f"  - {header}: {status}{value_str}")

        recommendations = data.get("recommendations", [])
        if recommendations:
            report.append("\nRecommendations:")
            for rec in recommendations:
                report.append(f"  • {rec}")

    report.append("\n")
    return "\n".join(report)


def export_txt_smtp(data: Dict[str, Any]) -> str:
    """Formats SMTP analysis for the text report."""
    report = ["--- Mail Server (SMTP) Analysis ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
        report.append("\n")
        return "\n".join(report)

    for server, info in data.items():
        report.append(f"\nServer: {server}")
        if info.get("error"):
            report.append(f"  - Error: {info['error']}")
            continue
        
        report.append(f"  - Banner: {info.get('banner', 'N/A')}")
        report.append(f"  - STARTTLS: {info.get('starttls', 'Unknown')}")

        cert_info = info.get('certificate')
        if cert_info:
            report.append("  - Certificate:")
            report.append(f"    - Subject: {cert_info.get('subject', 'N/A')}")
            valid_until_ts = cert_info.get('valid_until')
            if valid_until_ts:
                valid_until_dt = datetime.datetime.fromtimestamp(valid_until_ts).strftime('%Y-%m-%d')
                report.append(f"    - Valid Until: {valid_until_dt}")
    report.append("\n")
    return "\n".join(report)

def export_txt_reputation(data: Dict[str, Any]) -> str:
    """Formats IP reputation analysis for the text report."""
    report = ["--- IP Reputation Analysis (AbuseIPDB) ---"]
    if data.get("error"):
        report.append(f"Error: {data['error']}")
        report.append("\n")
        return "\n".join(report)

    for ip, info in data.items():
        report.append(f"\nIP Address: {ip}")
        if info.get("error"):
            report.append(f"  - Error: {info['error']}")
            continue
        
        report.append(f"  - Abuse Confidence Score: {info.get('abuseConfidenceScore', 'N/A')}")
        report.append(f"  - Total Reports: {info.get('totalReports', 'N/A')}")
        report.append(f"  - ISP: {info.get('isp', 'N/A')}")
        report.append(f"  - Usage Type: {info.get('usageType', 'N/A')}")
        
        if info.get('lastReportedAt'):
            last_reported = datetime.datetime.fromisoformat(info['lastReportedAt'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
            report.append(f"  - Last Reported: {last_reported}")

    report.append("\n")
    return "\n".join(report)