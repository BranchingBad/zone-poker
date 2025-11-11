#!/usr/bin/env python3
"""
Zone-poker - Display Module
Contains all functions for rendering rich output to the console
and formatting text for reports.
"""
import datetime
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich import box
from rich.text import Text
# Import shared config and utilities
from .config import console, RECORD_TYPES
from .display_utils import console_display_handler
from typing import Dict, List, Any, Callable

@console_display_handler("DNS Records Discovery")
def display_dns_records_table(records: Dict[str, List[Any]], quiet: bool = False):
    """Display DNS records in a beautiful table."""
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
    
    console.print(table)
    console.print(f"Total: {total_records} DNS records found")

@console_display_handler("Reverse DNS (PTR) Lookups")
def display_ptr_lookups(ptr_records: Dict[str, str], quiet: bool = False):
    """Displays PTR records in a table."""
    table = Table(title="Reverse DNS (PTR) Lookups", box=box.ROUNDED, show_header=True, header_style=None)
    table.add_column("IP Address", width=20)
    table.add_column("Hostname", max_width=60)

    if not ptr_records or "error" in ptr_records:
        console.print(Panel("[dim]No PTR records to display.[/dim]", title="Reverse DNS (PTR) Lookups", box=box.ROUNDED))
        return

    for ip, hostname in ptr_records.items():
        table.add_row(ip, hostname)

    console.print(table)
    console.print(f"Total: {len(ptr_records)} PTR lookups performed")

@console_display_handler("Zone Transfer (AXFR)")
def display_axfr_results(data: dict, quiet: bool = False):
    """Displays Zone Transfer (AXFR) results in a tree."""
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

@console_display_handler("Email Security Analysis")
def display_email_security(data: dict, quiet: bool = False):
    """Displays Email Security results in a table."""
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

@console_display_handler("WHOIS Information")
def display_whois_info(data: dict, quiet: bool = False):
    """Displays WHOIS data in a rich panel."""
    # --- THIS IS THE FIX ---
    if not isinstance(data, dict):
        console.print(Panel(f"[dim]Could not display WHOIS data. Received unexpected format: {str(data)}[/dim]", title="WHOIS Information", box=box.ROUNDED, border_style="dim"))
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

@console_display_handler("Nameserver Analysis")
def display_nameserver_analysis(data: dict, quiet: bool = False):
    """Displays Nameserver Analysis in a table."""
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
            
        # --- THIS BLOCK IS FIXED ---
        # Check if info is a dictionary before trying to access it.
        # This handles the case where the 'records' module fails and
        # 'nameserver_analysis' returns {"error": "..."}
        if isinstance(info, dict) and "error" in info:
            table.add_row(ns, f"[red]{info['error']}[/red]", "")
        elif isinstance(info, dict):
            ip_list = info.get('ips', [])
            ip_str = "\n".join(ip_list) if ip_list else "N/A"
            table.add_row(ns, ip_str, info.get('asn_description', 'N/A'))
            
    console.print(table)

@console_display_handler("DNS Propagation Check")
def display_propagation(data: dict, quiet: bool = False):
    """Displays DNS Propagation check results in a table."""
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

@console_display_handler("Security Audit")
def display_security_audit(data: dict, quiet: bool = False):
    """Displays Security Audit results in a table."""
    table = Table(title="Security Audit", box=box.ROUNDED, show_header=True, header_style=None)
    table.add_column("Check", style="bold")
    table.add_column("Result", max_width=50)

    for check, result in data.items():
        color = "red" if "Weak" in result or "Not Found" in result else "green" if "Secure" in result or "Present" in result else "yellow"
        table.add_row(check, f"[{color}]{result}[/{color}]")

    console.print(table)

@console_display_handler("Technology Detection")
def display_technology_info(data: dict, quiet: bool = False):
    """Displays Technology Detection results in a panel."""
    tree = Tree(f"[bold]Server:[/bold] {data.get('server', 'N/A')}")
    
    tech = data.get('technologies')
    if tech:
        tech_str = ", ".join(tech)
        tree.add(f"[bold]Technologies:[/bold] {tech_str}")
    
    headers_data = data.get('headers')
    if isinstance(headers_data, dict):
        sec_headers = [
            'strict-transport-security', 'content-security-policy', 
            'x-content-type-options', 'x-frame-options'
        ]
        header_tree = tree.add("[bold]Security Headers:[/bold]")
        for h in sec_headers:
            if h in headers_data:
                header_tree.add(f"[green]✓ {h}[/green]: {headers_data[h]}")
            else:
                header_tree.add(f"[red]✗ {h}[/red]: Not Found")

    console.print(Panel(tree, title="Technology Detection", box=box.ROUNDED))

@console_display_handler("OSINT Enrichment")
def display_osint_results(data: dict, quiet: bool = False):
    """Displays OSINT results in a tree."""
    tree = Tree("[bold]OSINT Enrichment[/bold]")

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

@console_display_handler("SSL/TLS Certificate Analysis")
def display_ssl_info(data: dict, quiet: bool = False):
    """Displays SSL/TLS Certificate analysis in a panel."""
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

@console_display_handler("Mail Server (SMTP) Analysis")
def display_smtp_info(data: dict, quiet: bool = False):
    """Displays Mail Server (SMTP) analysis in a panel."""
    tree = Tree("[bold]SMTP Server Analysis[/bold]")
    for server, info in data.items():
        if isinstance(info, dict):
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
        else:
            tree.add(f"✗ [red]{server}[/red]: Error - {str(info)}")

    console.print(Panel(tree, title="Mail Server (SMTP) Analysis", box=box.ROUNDED))

@console_display_handler("IP Reputation Analysis (AbuseIPDB)")
def display_reputation_info(data: dict, quiet: bool = False):
    """Displays IP Reputation analysis in a panel."""
    tree = Tree("[bold]IP Reputation Analysis (AbuseIPDB)[/bold]")
    for ip, info in data.items():
        if isinstance(info, dict):
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
        else:
            # Handle case where info is not a dict (e.g., an error string)
            tree.add(f"✗ [red]{ip}[/red]: Error - {str(info)}")

    console.print(Panel(tree, title="IP Reputation Analysis (AbuseIPDB)", box=box.ROUNDED))

@console_display_handler("Content & Favicon Hashes")
def display_content_hash_info(data: dict, quiet: bool = False):
    """Displays Favicon and Content Hash results in a panel."""
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column("Key", style="bold cyan", no_wrap=True, width=25)
    table.add_column("Value")

    if data.get("favicon_murmur32_hash"):
        table.add_row("Favicon Murmur32 Hash:", data["favicon_murmur32_hash"])
    if data.get("page_sha256_hash"):
        table.add_row("Page Content SHA256:", data["page_sha256_hash"])

    console.print(Panel(table, title="Content & Favicon Hashes", box=box.ROUNDED, expand=False))

@console_display_handler("Certificate Transparency Log Analysis")
def display_ct_logs(data: dict, quiet: bool = False):
    """Displays Certificate Transparency Log results in a tree."""
    subdomains = data.get('subdomains', [])
    tree = Tree(f"[bold]Certificate Transparency Log Analysis ({len(subdomains)} found)[/bold]")

    if subdomains:
        for s in subdomains:
            tree.add(f"[green]{s}[/green]")
    else:
        tree.add("[dim]No subdomains found in CT logs.[/dim]")

    console.print(tree)

@console_display_handler("WAF Detection")
def display_waf_detection(data: dict, quiet: bool = False):
    """Displays WAF Detection results in a panel."""
    detected_waf = data.get("detected_waf", "None")
    if detected_waf != "None":
        color = "green"
        reason = data.get("details", {}).get("reason", "")
        message = f"Identified [bold]{detected_waf}[/bold]. [dim]({reason})[/dim]"
    else:
        color = "dim"
        message = "No WAF identified."
    console.print(Panel(f"[{color}]{message}[/{color}]", title="WAF Detection", box=box.ROUNDED))

@console_display_handler("DANE/TLSA Record Analysis")
def display_dane_analysis(data: dict, quiet: bool = False):
    """Displays DANE/TLSA analysis in a panel."""
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

def display_summary(data: dict, quiet: bool):
    """Displays a high-level summary of findings."""
    if quiet:
        return
        
    table = Table(title="Scan Summary", box=box.ROUNDED, show_header=False, header_style=None)
    table.add_column("Module", style="bold cyan")
    table.add_column("Finding")
    
    # Zone Transfer
    zone_info = data.get('zone_info', {})
    axfr_summary = zone_info.get('summary', 'N/A') if isinstance(zone_info, dict) else 'Error'
    axfr_color = "bold red" if "Vulnerable" in axfr_summary else "green"
    table.add_row("Zone Transfer", f"[{axfr_color}]{axfr_summary}[/{axfr_color}]")
    
    # SPF
    email_sec = data.get('email_security', {})
    spf_data = email_sec.get('spf', {}) if isinstance(email_sec, dict) else {}
    spf_policy = spf_data.get('all_policy', 'Not Found') if isinstance(spf_data, dict) else 'Error'
    spf_color = "red" if spf_policy in ["?all", "Not Found"] else "yellow" if spf_policy == "~all" else "green"
    table.add_row("SPF Policy", f"[{spf_color}]{spf_policy}[/{spf_color}]")
    
    # DMARC
    dmarc_data = email_sec.get('dmarc', {}) if isinstance(email_sec, dict) else {}
    dmarc_policy = dmarc_data.get('p', 'Not Found') if isinstance(dmarc_data, dict) else 'Error'
    dmarc_color = "red" if dmarc_policy in ["none", "Not Found", "Error"] else "green"
    table.add_row("DMARC Policy", f"[{dmarc_color}]{dmarc_policy}[/{dmarc_color}]")

    # Security Audit
    audit_findings = data.get('security', {})
    if isinstance(audit_findings, dict):
        weak_findings = [k for k, v in audit_findings.items() if isinstance(v, str) and ("Weak" in v or "Not Found" in v)]
        if weak_findings:
            table.add_row("Security Audit", f"[red]Found {len(weak_findings)} issues[/red] ({', '.join(weak_findings)})")
        else:
            table.add_row("Security Audit", "[green]All checks passed[/green]")
    else:
        table.add_row("Security Audit", "[bold red]Error processing audit data[/bold red]")

    console.print(table)
    console.print()

def display_critical_findings(data: dict, quiet: bool):
    """Displays a summary of only the most critical findings."""
    if quiet:
        return

    critical_findings = []

    # Zone Transfer Vulnerability
    if "Vulnerable" in data.get('zone_info', {}).get('summary', ''):
        critical_findings.append("Zone Transfer Successful (AXFR): Domain is vulnerable to full zone enumeration.")

    # Subdomain Takeover
    vulnerable_takeovers = data.get('takeover_info', {}).get('vulnerable', [])
    if vulnerable_takeovers:
        critical_findings.append(f"Subdomain Takeover: Found {len(vulnerable_takeovers)} potentially vulnerable subdomains.")

    # Expired SSL Certificate
    ssl_info = data.get('ssl_info', {})
    if ssl_info.get('valid_until'):
        if datetime.datetime.now().timestamp() > ssl_info['valid_until']:
            critical_findings.append("Expired SSL/TLS Certificate: The main web server's certificate has expired.")

    # High IP Reputation Abuse Score
    reputation_info = data.get('reputation_info', {})
    high_risk_ips = [ip for ip, info in reputation_info.items() if isinstance(info, dict) and info.get('abuseConfidenceScore', 0) > 75]
    if high_risk_ips:
        critical_findings.append(f"High-Risk IP Reputation: {len(high_risk_ips)} IP(s) have a high abuse score ({', '.join(high_risk_ips)}).")

    if not critical_findings:
        return # Don't display the panel if there's nothing critical

    text = Text()
    for finding in critical_findings:
        text.append("• ", style="bold red")
        text.append(f"{finding}\n")

    panel = Panel(text, title="[bold red]🚨 Critical Findings[/bold red]", box=box.ROUNDED, border_style="red")
    console.print(panel)
    console.print()

# -----------------------------------------------------------------
# --- TXT REPORT EXPORT FUNCTIONS ---
# -----------------------------------------------------------------
# These functions are called by the export module to format
# data for the .txt report.
# -----------------------------------------------------------------

def _create_report_section(title: str, data: Dict[str, Any], formatter: Callable[[Dict[str, Any]], List[str]]) -> str:
    """
    A helper to create a formatted text report section with a standard header and error handling.
    """
    report = ["="*15 + f" {title} " + "="*15]
    
    if not isinstance(data, dict):
        report.append(f"  Error: Unexpected data format for {title}. Expected dictionary, got {type(data).__name__}.")
        if data: # If it's a non-empty string or other non-dict, include its representation
            report.append(f"  Raw data: {data}")
        return "\n".join(report)

    # Now we are sure 'data' is a a dictionary
    if not data: # Check if the dictionary is empty
        report.append("No data found for this section.")
    elif data.get("error"):
        report.append(f"  Error: {data['error']}")
    else:
        # The formatter function returns a list of content lines
        report.extend(formatter(data))
    return "\n".join(report)

def export_txt_critical_findings(data: Dict[str, Any]) -> str:
    """Formats a summary of critical findings for the text report."""
    critical_findings = []

    # Zone Transfer Vulnerability
    if "Vulnerable" in data.get('zone_info', {}).get('summary', ''):
        critical_findings.append("Zone Transfer Successful (AXFR): Domain is vulnerable to full zone enumeration.")

    # Subdomain Takeover
    vulnerable_takeovers = data.get('takeover_info', {}).get('vulnerable', [])
    if vulnerable_takeovers:
        critical_findings.append(f"Subdomain Takeover: Found {len(vulnerable_takeovers)} potentially vulnerable subdomains.")

    # Expired SSL Certificate
    ssl_info = data.get('ssl_info', {})
    if ssl_info.get('valid_until'):
        if datetime.datetime.now().timestamp() > ssl_info['valid_until']:
            critical_findings.append("Expired SSL/TLS Certificate: The main web server's certificate has expired.")

    # High IP Reputation Abuse Score
    reputation_info = data.get('reputation_info', {})
    high_risk_ips = [ip for ip, info in reputation_info.items() if isinstance(info, dict) and info.get('abuseConfidenceScore', 0) > 75]
    if high_risk_ips:
        critical_findings.append(f"High-Risk IP Reputation: {len(high_risk_ips)} IP(s) have a high abuse score ({', '.join(high_risk_ips)}).")

    if not critical_findings:
        return "" # Return an empty string if there are no critical findings

    report = ["="*15 + " CRITICAL FINDINGS " + "="*15]
    report.extend([f"  • {finding}" for finding in critical_findings])
    return "\n".join(report)

def export_txt_summary(data: Dict[str, Any]) -> str:
    """Formats a high-level summary for the text report."""
    report = ["="*15 + " Scan Summary " + "="*15]
    
    # Zone Transfer
    axfr_summary = data.get('zone_info', {}).get('summary', 'Not Found')
    report.append(f"  {'Zone Transfer:':<20}: {axfr_summary}")

    # SPF Policy
    spf_policy = data.get('email_security', {}).get('spf', {}).get('all_policy', 'Not Found')
    report.append(f"  {'SPF Policy:':<20}: {spf_policy}")

    # DMARC Policy
    dmarc_policy = data.get('email_security', {}).get('dmarc', {}).get('p', 'Not Found')
    report.append(f"  {'DMARC Policy:':<20}: {dmarc_policy}")

    # Security Audit
    audit_findings = data.get('security', {})
    if audit_findings:
        weak_findings = [k for k, v in audit_findings.items() if "Weak" in v or "Not Found" in v]
        if weak_findings:
            summary_text = f"Found {len(weak_findings)} issues ({', '.join(weak_findings)})"
        else:
            summary_text = "All checks passed"
        report.append(f"  {'Security Audit:':<20}: {summary_text}")

    return "\n".join(report)

def _format_records_txt(data: Dict[str, List[Any]]) -> List[str]:
    """Formats DNS records for the text report."""
    total_records = 0
    # --- THIS IS THE FIX ---
    if "error" in data:
        return [f"Could not retrieve DNS records: {data['error']}"]

    report = []
    for r_type, items in data.items():
        if items:
            if total_records > 0: report.append("") # Add space between types
            report.append(f"[{r_type}]")
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
    return report

def export_txt_records(data: Dict[str, List[Any]]) -> str:
    return _create_report_section("DNS Records", data, _format_records_txt)

def _format_ptr_txt(data: Dict[str, str]) -> List[str]:
    """Formats PTR lookups for the text report."""
    if not data:
        return ["No PTR records found."]
    return [f"  - {ip:<18} -> {hostname}" for ip, hostname in data.items()]

def export_txt_ptr(data: Dict[str, str]) -> str:
    return _create_report_section("Reverse DNS (PTR) Lookups", data, _format_ptr_txt)

def _format_zone_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Zone Transfer results for the text report."""
    report = []
    report.append(f"Overall Status: {data.get('summary', data.get('status', 'No data.'))}")
    for server, info in data.get('servers', {}).items():
        report.append(f"  - {server}: {info['status']}")
        if info['status'] == 'Successful':
            report.append(f"    Record Count: {info['record_count']}")
    report.append("\n")
    return report

def export_txt_zone(data: Dict[str, Any]) -> str:
    return _create_report_section("Zone Transfer (AXFR)", data, _format_zone_txt)

def _format_mail_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Email Security analysis for the text report."""
    report = []
    for key, value in data.items():
        report.append(f"\n[{key.upper()}]")
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                report.append(f"  - {sub_key:<15}: {sub_value}")
        else:
            report.append(f"  - {value}")
    return report

def export_txt_mail(data: Dict[str, Any]) -> str:
    return _create_report_section("Email Security", data, _format_mail_txt)

def _format_whois_txt(data: Dict[str, Any]) -> List[str]:
    """Formats WHOIS information for the text report."""
    # --- THIS IS THE FIX ---
    if not isinstance(data, dict):
        return [f"Could not format WHOIS data. Expected a dictionary, but received: {str(data)}"]

    report = []
    for key, value in data.items():
        if value and key != "error":
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
            report.append(f"  {key.replace('_', ' ').title():<20}: {value_str}")
    return report

def export_txt_whois(data: Dict[str, Any]) -> str:
    return _create_report_section("WHOIS Information", data, _format_whois_txt)

def _format_nsinfo_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Nameserver Analysis for the text report."""
    report = []
    # --- THIS IS THE FIX ---
    if "error" in data:
        return [f"Could not analyze nameservers: {data['error']}"]

    dnssec_status = data.get("dnssec", "Unknown") # Safe, data is dict
    for ns, info in data.items(): # info can be Dict or str
        if ns == "dnssec": 
            continue
        if isinstance(info, dict):
            ip_list = info.get('ips', [])
            ip_str = ", ".join(ip_list) if ip_list else "N/A" # Use comma for TXT
            asn = info.get('asn_description', 'N/A')
            report.append(f"  - {ns}")
            report.append(f"    IP(s): {ip_str}")
            report.append(f"    ASN: {asn}")
        else:
            report.append(f"  - {ns}: Unexpected data format - {str(info)}")
    report.append(f"\nDNSSEC: {dnssec_status}") # Safe
    return report

def export_txt_nsinfo(data: Dict[str, Any]) -> str:
    return _create_report_section("Nameserver Analysis", data, _format_nsinfo_txt)

def _format_propagation_txt(data: Dict[str, str]) -> List[str]:
    """Formats DNS Propagation check for the text report."""
    return [f"  - {server:<20}: {ip}" for server, ip in data.items()]

def export_txt_propagation(data: Dict[str, str]) -> str:
    return _create_report_section("DNS Propagation Check", data, _format_propagation_txt)

def _format_security_txt(data: Dict[str, str]) -> List[str]:
    """Formats Security Audit for the text report."""
    return [f"  - {check:<25}: {result}" for check, result in data.items()]

def export_txt_security(data: Dict[str, str]) -> str:
    return _create_report_section("Security Audit", data, _format_security_txt)

def _format_tech_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Technology Detection for the text report."""
    report = []
    if data.get("technologies"):
        report.append(f"  {'Technologies:':<20}: {', '.join(data['technologies'])}")
    if data.get("server"):
        report.append(f"  {'Server:':<20}: {data['server']}")
    headers_data = data.get("headers")
    if isinstance(headers_data, dict): # Check if headers_data is a dictionary
        report.append("\nSecurity Headers:")
        for h_key, h_value in headers_data.items():
            report.append(f"  - {h_key}: {h_value}")
    elif headers_data: # If it's not a dict but not empty (e.g., an error string)
        report.append(f"\nSecurity Headers: {headers_data}")
    return report

def export_txt_tech(data: Dict[str, Any]) -> str:
    return _create_report_section("Technology Detection", data, _format_tech_txt)

def _format_osint_txt(data: Dict[str, Any]) -> List[str]:
    """Formats OSINT Enrichment for the text report."""
    report = []
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

    return report

def export_txt_osint(data: Dict[str, Any]) -> str:
    return _create_report_section("OSINT Enrichment", data, _format_osint_txt)

def _format_content_hash_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Content Hash analysis for the text report."""
    report = []
    if data.get("favicon_murmur32_hash"):
        report.append(f"  {'Favicon Murmur32 Hash:':<25}: {data['favicon_murmur32_hash']}")
    if data.get("page_sha256_hash"):
        report.append(f"  {'Page Content SHA256:':<25}: {data['page_sha256_hash']}")
    return report

def export_txt_content_hash(data: Dict[str, Any]) -> str:
    return _create_report_section("Content & Favicon Hashes", data, _format_content_hash_txt)

def _format_ct_logs_txt(data: Dict[str, Any]) -> List[str]:
    """Formats CT Log analysis for the text report."""
    report = []
    subdomains = data.get('subdomains', [])
    if subdomains:
        report.append(f"Found {len(subdomains)} subdomains:")
        for item in subdomains:
            report.append(f"  - {item}")
    else:
        report.append("No subdomains found in CT logs.")
    return report

def export_txt_ct_logs(data: Dict[str, Any]) -> str:
    return _create_report_section("Certificate Transparency Log Analysis", data, _format_ct_logs_txt)

def _format_waf_detection_txt(data: Dict[str, Any]) -> List[str]:
    """Formats WAF Detection analysis for the text report."""
    detected_waf = data.get("detected_waf", "None")
    if detected_waf != "None":
        reason = data.get("details", {}).get("reason", "")
        return [f"Identified: {detected_waf} (Reason: {reason})"]
    return ["No WAF identified from response headers."]

def export_txt_waf_detection(data: Dict[str, Any]) -> str:
    return _create_report_section("WAF Detection", data, _format_waf_detection_txt)

def _format_dane_txt(data: Dict[str, Any]) -> List[str]:
    """Formats DANE/TLSA analysis for the text report."""
    report = []
    status = data.get("status", "Not Found")
    report.append(f"Status for _443._tcp (HTTPS): {status}")
    records = data.get("records", [])
    if records:
        report.append("\nRecords:")
        report.extend([f"  - {record}" for record in records])
    return report

def export_txt_dane(data: Dict[str, Any]) -> str:
    return _create_report_section("DANE/TLSA Record Analysis", data, _format_dane_txt)

@console_display_handler("HTTP Security Headers Analysis")
def display_http_headers(data: dict, quiet: bool):
    """Displays HTTP Security Header analysis in a panel."""
    if not isinstance(data, dict):
        console.print(Panel(f"[dim]Could not display HTTP Headers. Received unexpected format: {str(data)}[/dim]", title="HTTP Security Headers Analysis", box=box.ROUNDED, border_style="dim"))
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

@console_display_handler("Open Port Scan")
def display_port_scan(data: dict, quiet: bool = False):
    """Displays Open Port Scan results in a table."""
    table = Table(title="Open Port Scan", box=box.ROUNDED, show_header=True, header_style=None)
    table.add_column("IP Address", style="bold", width=20)
    table.add_column("Open Ports")

    if not data or "error" in data:
        console.print(Panel("[dim]No port scan data to display.[/dim]", title="Open Port Scan", box=box.ROUNDED))
        return

    for ip, ports in data.items():
        ports_str = ", ".join(map(str, ports))
        table.add_row(ip, f"[green]{ports_str}[/green]")
    console.print(table)

@console_display_handler("Subdomain Takeover")
def display_subdomain_takeover(data: dict, quiet: bool = False):
    """Displays Subdomain Takeover results in a panel."""
    vulnerable = data.get("vulnerable", [])
    
    if not vulnerable:
        panel = Panel("[green]✓ No potential subdomain takeovers found.[/green]", title="Subdomain Takeover", box=box.ROUNDED)
    else:
        tree = Tree(f"[bold red]✗ Found {len(vulnerable)} potential subdomain takeovers![/bold red]")
        for item in vulnerable:
            node = tree.add(f"[yellow]{item['subdomain']}[/yellow]")
            node.add(f"Service: [bold]{item['service']}[/bold]")
            node.add(f"CNAME Target: [dim]{item['cname_target']}[/dim]")
        panel = Panel(tree, title="Subdomain Takeover", box=box.ROUNDED, border_style="red")

    console.print(panel)

@console_display_handler("Cloud Service Enumeration")
def display_cloud_enum(data: dict, quiet: bool = False):
    """Displays Cloud Enumeration results in a panel."""
    s3_buckets = data.get("s3_buckets", [])
    azure_blobs = data.get("azure_blobs", [])
    
    if not s3_buckets and not azure_blobs:
        panel = Panel("[dim]No public S3 buckets or Azure blobs found based on common permutations.[/dim]", title="Cloud Service Enumeration", box=box.ROUNDED)
    else:
        tree = Tree("[bold]Cloud Service Enumeration[/bold]")
        if s3_buckets:
            s3_tree = tree.add(f"Discovered S3 Buckets ({len(s3_buckets)}):")
            for bucket in s3_buckets:
                status = bucket.get("status")
                url = bucket.get("url")
                if status == "public":
                    symbol = "✅"
                    color = "green"
                elif status == "forbidden":
                    symbol = "🔒"
                    color = "yellow"
                else:
                    symbol = "❓"
                    color = "dim"
                s3_tree.add(f"{symbol} [{color}]{url}[/{color}]")

        if azure_blobs:
            azure_tree = tree.add(f"Discovered Azure Blob Containers ({len(azure_blobs)}):")
            for blob in azure_blobs:
                status = blob.get("status")
                url = blob.get("url")
                if status == "public":
                    symbol = "✅"
                    color = "green"
                elif status == "forbidden":
                    symbol = "🔒"
                    color = "yellow"
                else:
                    symbol = "❓"
                    color = "dim"
                azure_tree.add(f"{symbol} [{color}]{url}[/{color}]")
        panel = Panel(tree, title="Cloud Service Enumeration", box=box.ROUNDED)

    console.print(panel)

@console_display_handler("DNS Blocklist (DNSBL) Check")
def display_dnsbl_check(data: dict, quiet: bool = False):
    """Displays DNSBL check results in a panel."""
    listed_ips = data.get("listed_ips", [])

    if not listed_ips:
        panel = Panel("[green]✓ No discovered IPs were found on common DNS blocklists.[/green]", title="DNS Blocklist (DNSBL) Check", box=box.ROUNDED)
    else:
        tree = Tree(f"[bold red]✗ Found {len(listed_ips)} IP(s) on DNS blocklists![/bold red]")
        for item in listed_ips:
            node = tree.add(f"[yellow]{item['ip']}[/yellow]")
            node.add(f"Listed on: [dim]{', '.join(item.get('listed_on', []))}[/dim]")
        panel = Panel(tree, title="DNS Blocklist (DNSBL) Check", box=box.ROUNDED, border_style="red")

    console.print(panel)


def _format_http_headers_txt(data: Dict[str, Any]) -> List[str]:
    """Formats HTTP Security Headers for the text report."""
    report = [f"Final URL: {data.get('final_url')}\n"]
    analysis = data.get("analysis", {})
    for header, info in analysis.items():
        status = info.get("status", "Unknown")
        value = info.get("value", "")
        value_str = f" - Value: {value}" if value else ""
        report.append(f"  - {header}: {status}{value_str}")

    recommendations = data.get("recommendations", [])
    if recommendations:
        report.append("\nRecommendations:")
        report.extend([f"  • {rec}" for rec in recommendations])
    return report

def export_txt_http_headers(data: Dict[str, Any]) -> str:
    """Formats HTTP Security Headers for the text report."""
    return _create_report_section("HTTP Security Headers Analysis", data, _format_http_headers_txt)

def _format_cloud_enum_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Cloud Enumeration for the text report."""
    report = []
    s3_buckets = data.get("s3_buckets", [])
    azure_blobs = data.get("azure_blobs", [])

    if not s3_buckets and not azure_blobs:
        report.append("No public S3 or Azure Blob containers found based on common permutations.")
    if s3_buckets:
        report.append("Discovered S3 Buckets:")
        for bucket in s3_buckets:
            status = bucket.get("status")
            url = bucket.get("url")
            if status == "public":
                symbol = "✅"
            elif status == "forbidden":
                symbol = "🔒"
            else:
                symbol = "❓"
            report.append(f"  {symbol} {url}")
    if azure_blobs:
        if s3_buckets: report.append("") # Add a newline if S3 buckets were also found
        report.append("Discovered Azure Blob Containers:")
        for blob in azure_blobs:
            status = blob.get("status")
            url = blob.get("url")
            if status == "public":
                symbol = "✅"
            elif status == "forbidden":
                symbol = "🔒"
            else:
                symbol = "❓"
            report.append(f"  {symbol} {url}")
    return report

@console_display_handler("IP Geolocation")
def display_ip_geolocation(data: dict, quiet: bool = False):
    """Displays IP Geolocation results in a table."""
    table = Table(title="IP Geolocation", box=box.ROUNDED, show_header=True, header_style=None)
    table.add_column("IP Address", style="bold", width=20)
    table.add_column("Country")
    table.add_column("City")
    table.add_column("ISP")

    for ip, info in data.items():
        if isinstance(info, dict):
            if info.get("error"):
                table.add_row(ip, f"[red]{info['error']}[/red]", "", "")
            else:
                table.add_row(
                    ip,
                    info.get("country", "N/A"),
                    info.get("city", "N/A"),
                    info.get("isp", "N/A"),
                )
        else: # Handle case where info is not a dict (e.g., an error string)
            table.add_row(
                ip, f"[red]Error: {str(info)}[/red]", "", ""
            )
    console.print(table)

def export_txt_ssl(data: Dict[str, Any]) -> str:
    """Formats SSL/TLS analysis for the text report."""
    return _create_report_section("SSL/TLS Certificate Analysis", data, _format_ssl_txt)

def export_txt_geolocation(data: Dict[str, Any]) -> str:
    """Formats IP Geolocation for the text report."""
    return _create_report_section("IP Geolocation", data, _format_geolocation_txt)

def _format_port_scan_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Open Port Scan for the text report."""
    if not data:
        return ["No open ports found among common ports."]
    report = []
    for ip, ports in data.items():
        ports_str = ", ".join(map(str, ports))
        report.append(f"  - {ip}: {ports_str}")
    return report

def export_txt_port_scan(data: Dict[str, Any]) -> str:
    """Formats Open Port Scan for the text report."""
    return _create_report_section("Open Port Scan", data, _format_port_scan_txt)

def export_txt_cloud_enum(data: Dict[str, Any]) -> str:
    """Formats Cloud Enumeration for the text report."""
    return _create_report_section("Cloud Service Enumeration", data, _format_cloud_enum_txt)

def _format_dnsbl_check_txt(data: Dict[str, Any]) -> List[str]:
    """Formats DNSBL check for the text report."""
    listed_ips = data.get("listed_ips", [])
    if not listed_ips:
        return ["No IP addresses found on common DNS blocklists."]
    report = [f"Found {len(listed_ips)} IP(s) on DNS blocklists:"]
    for item in listed_ips:
        report.append(f"\n  - IP Address: {item['ip']}")
        report.append(f"    Listed on: {', '.join(item.get('listed_on', []))}")
    return report

def export_txt_dnsbl_check(data: Dict[str, Any]) -> str:
    """Formats DNSBL check for the text report."""
    return _create_report_section("DNS Blocklist (DNSBL) Check", data, _format_dnsbl_check_txt)

def _format_subdomain_takeover_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Subdomain Takeover for the text report."""
    vulnerable = data.get("vulnerable", [])
    if not vulnerable:
        return ["No potential subdomain takeovers found."]
    report = [f"Found {len(vulnerable)} potential subdomain takeovers:"]
    for item in vulnerable:
        report.append(f"\n  - Subdomain: {item['subdomain']}")
        report.append(f"    Service: {item['service']}")
        report.append(f"    CNAME Target: {item['cname_target']}")
    return report

def export_txt_subdomain_takeover(data: Dict[str, Any]) -> str:
    """Formats Subdomain Takeover for the text report."""
    return _create_report_section("Subdomain Takeover", data, _format_subdomain_takeover_txt)

def export_txt_smtp(data: Dict[str, Any]) -> str:
    """Formats SMTP analysis for the text report."""
    return _create_report_section("Mail Server (SMTP) Analysis", data, _format_smtp_txt)

def _format_smtp_txt(data: Dict[str, Any]) -> List[str]:
    """Formats SMTP analysis for the text report."""
    if not data:
        return ["No SMTP servers were analyzed."]
    report = []
    for server, info in data.items(): # info can be Dict or str if an error occurred for that specific server
        if isinstance(info, dict):
            if info.get("error"):
                report.append(f"  - {server}: Error - {info['error']}")
                continue
            
            report.append(f"  - {server}")
            report.append(f"    Banner: {info.get('banner', 'N/A')}")
            report.append(f"    STARTTLS: {info.get('starttls', 'Unknown')}")
            
            cert_info = info.get('certificate')
            if cert_info:
                report.append("    Certificate:")
                report.append(f"      Subject: {cert_info.get('subject', 'N/A')}")
                report.append(f"      Valid Until: {datetime.datetime.fromtimestamp(cert_info['valid_until']).strftime('%Y-%m-%d %H:%M:%S') if cert_info.get('valid_until') else 'N/A'}")
        else:
            report.append(f"  - {server}: Unexpected data format - {str(info)}")
    return report

def _format_geolocation_txt(data: Dict[str, Any]) -> List[str]:
    """Formats IP Geolocation for the text report."""
    if not data:
        return ["No IP addresses were geolocated."]
    report = []
    for ip, info in data.items():
        if info.get("error"):
            report.append(f"  - {ip}: Error - {info['error']}")
        else:
            country = info.get('country', 'N/A')
            city = info.get('city', 'N/A')
            isp = info.get('isp', 'N/A')
            report.append(f"  - {ip}: {city}, {country} (ISP: {isp})")
    return report

def _format_ssl_txt(data: Dict[str, Any]) -> List[str]:
    """Formats SSL/TLS analysis for the text report."""
    report = [
        f"Subject: {data['subject']}",
        f"Issuer: {data['issuer']}",
        f"Valid From: {datetime.datetime.fromtimestamp(data['valid_from']).strftime('%Y-%m-%d %H:%M:%S')}",
        f"Valid Until: {datetime.datetime.fromtimestamp(data['valid_until']).strftime('%Y-%m-%d %H:%M:%S')}"
    ]
    if data['sans']:
        report.extend(["\nSubject Alternative Names:"] + [f"  - {s}" for s in data['sans']])
    return report

def export_txt_reputation(data: Dict[str, Any]) -> str:
    """Formats IP reputation analysis for the text report."""
    return _create_report_section("IP Reputation Analysis (AbuseIPDB)", data, _format_reputation_txt)

def _format_reputation_txt(data: Dict[str, Any]) -> List[str]:
    """Formats IP reputation analysis for the text report."""
    if not data:
        return ["No IP reputation data was found."]
    report = []
    for ip, info in data.items(): # info can be Dict or str if an error occurred for that specific IP
        if isinstance(info, dict):
            if info.get("error"):
                report.append(f"  - {ip}: Error - {info['error']}")
                continue
            
            score = info.get('abuseConfidenceScore', 0)
            last_reported = info.get('lastReportedAt', 'N/A')
            if last_reported != 'N/A':
                last_reported = datetime.datetime.fromisoformat(last_reported.replace('Z', '+00:00')).strftime('%Y-%m-%d')
            report.append(f"  - {ip}: Score: {score}, Reports: {info.get('totalReports', 0)}, Last Reported: {last_reported}")
        else:
            report.append(f"  - {ip}: Unexpected data format - {str(info)}")
    return report