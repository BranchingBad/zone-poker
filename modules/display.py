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
from typing import Dict, Any, List, Callable, Optional

# Import shared config and utilities
import logging

logger = logging.getLogger(__name__)


def _get_record_extra_info(rtype: str, record: Dict[str, Any]) -> str:
    """Helper to format the 'Extra' column for the DNS records table."""
    if rtype == "MX" and "priority" in record:
        return f"Priority: {record['priority']}"
    if rtype == "SRV":
        return (f"P:{record.get('priority')} W:{record.get('weight')} "
                f"Port:{record.get('port')}")
    if rtype == "SOA":
        return f"Serial: {record.get('serial')}"
    if rtype == "CAA":
        return f"Tag: {record.get('tag')}"
    return ""


def console_display_handler(title: str):
    """
    A decorator to handle common boilerplate for console display functions.
    - Checks for `quiet` mode or empty data.
    - Handles and displays a standardized error panel if `data['error']` exists.
    - Prints a newline after the content is displayed.
    """
    def decorator(func: Callable):
        def wrapper(data: dict, quiet: bool, *args, **kwargs) -> Optional[Panel]:
            if quiet or not data or not isinstance(data, dict):
                return None

            if error := data.get("error"):
                return Panel(f"[dim]{error}[/dim]", title=f"{title} - Error",
                             box=box.ROUNDED, border_style="dim")

            renderable = func(data, quiet, *args, **kwargs)
            return renderable
        return wrapper
    return decorator


@console_display_handler("DNS Records Discovery")
def display_dns_records_table(records: Dict[str, List[Any]], quiet: bool = False):
    """Creates a rich Table of DNS records."""
    table = Table(
        title="DNS Records Discovery",
        box=box.ROUNDED,
        show_header=True,
        header_style=None,
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

                extra = _get_record_extra_info(rtype, record)
                type_display = rtype if idx == 0 else ""

                if len(value) > 50:
                    value = value[:47] + "..."

                table.add_row(type_display, value, ttl, extra)

    if total_records == 0:
        table.add_row("No records found", "", "", "")

    table.caption = f"Total: {total_records} DNS records found"
    return table


@console_display_handler("Reverse DNS (PTR) Lookups")
def display_ptr_lookups(ptr_records: Dict[str, str], quiet: bool = False):
    """Creates a rich Table of PTR records."""
    table = Table(
        title="Reverse DNS (PTR) Lookups",
        box=box.ROUNDED,
        show_header=True,
        header_style=None,
    )
    table.add_column("IP Address", width=20)
    table.add_column("Hostname", max_width=60)

    if not ptr_records:
        return Panel(
            "[dim]No PTR records to display.[/dim]",
            title="Reverse DNS (PTR) Lookups",
            box=box.ROUNDED
        )

    for ip, hostname in ptr_records.items():
        table.add_row(ip, hostname)

    table.caption = f"Total: {len(ptr_records)} PTR lookups performed"
    return table


@console_display_handler("Zone Transfer (AXFR)")
def display_axfr_results(data: dict, quiet: bool = False):
    """Creates a rich Tree of Zone Transfer (AXFR) results."""
    summary = data.get("summary", data.get("status", "No data."))
    style = "bold red" if "Vulnerable" in summary else "bold green"

    tree = Tree(f"[bold]Zone Transfer (AXFR): [/bold][{style}]{summary}[/{style}]")

    servers = data.get("servers", {})
    for server, info in servers.items():
        status = info.get("status", "Unknown")
        if status == "Successful":
            tree.add(
                f"✓ [green]{server}: {status} ({info.get('record_count', 0)} records via {info.get('ip_used')})[/green]"
            )
        elif "Refused" in status:
            tree.add(f"✗ [yellow]{server}: {status}[/yellow]")
        else:
            tree.add(f"✗ [dim]{server}: {status}[/dim]")

    return tree


@console_display_handler("Email Security Analysis")
def display_email_security(data: dict, quiet: bool = False):
    """Displays Email Security results in a table."""
    table = Table(
        title="Email Security Analysis",
        box=box.ROUNDED,
        show_header=False,
        header_style=None,
    )
    table.add_column("Check", style="bold cyan", width=10)
    table.add_column("Result")

    # SPF
    spf_data = data.get("spf", {})
    if spf_data.get("status") == "Not Found":
        table.add_row("SPF", "[red]Not Found[/red]")
    elif spf_data.get("raw"):
        policy = spf_data.get("all_policy", "N/A")
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
        policy = dmarc_data.get("p", "N/A")
        color = "red" if policy == "none" else "green"
        table.add_row(
            "DMARC", f"{dmarc_data['raw']}\nPolicy: [{color}]{policy}[/{color}]"
        )

    # DKIM
    table.add_row("DKIM", data.get("dkim", {}).get("status", "N/A"))

    return table


@console_display_handler("WHOIS Information")
def display_whois_info(data: dict, quiet: bool = False):  # noqa: E501
    """Creates a rich Panel with WHOIS data."""
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column("Key", style="bold cyan", no_wrap=True, width=18)
    table.add_column("Value")

    # --- THIS SECTION IS REFACTORED ---
    # Iterate over all data items instead of a hardcoded list.
    # Exclude keys that are not helpful in the display.
    EXCLUDE_KEYS = {"error"}

    for key, value in data.items():
        if key in EXCLUDE_KEYS or not value:
            continue

        # --- THIS IS THE FIX for duplicate WHOIS data ---
        # If the value is a list, take the first element to deduplicate.
        if isinstance(value, list):
            if not value:
                continue
            value = value[0]

        elif "date" in key and isinstance(value, str):
            try:
                dt = datetime.datetime.fromisoformat(value)
                value_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                value_str = str(value)
        else:
            value_str = str(value)

        table.add_row(f"{key.replace('_', ' ').title()}:", value_str)
    # --- END REFACTOR ---

    return Panel(table, title="WHOIS Information", box=box.ROUNDED, expand=False)


@console_display_handler("Nameserver Analysis")
def display_nameserver_analysis(data: dict, quiet: bool = False):
    """Creates a rich Table for Nameserver Analysis."""
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
            ip_list = info.get("ips", [])
            ip_str = "\n".join(ip_list) if ip_list else "N/A"
            table.add_row(ns, ip_str, info.get("asn_description", "N/A"))

    return table


@console_display_handler("DNS Propagation Check")
def display_propagation(data: dict, quiet: bool = False, **kwargs):
    """Displays DNS Propagation check results in a table."""
    table = Table(
        title="DNS Propagation Check",
        box=box.ROUNDED,
        show_header=True,
        header_style=None,
        caption_justify="right",
    )
    table.add_column("Resolver", style="bold")
    table.add_column("IP Address(es)")

    all_ips = set()
    for result in data.values():
        if result.get("ips"):
            all_ips.update(result["ips"])

    # A list of distinct, named colors that are safe for most terminals.
    # We'll cycle through these colors for different IPs.
    safe_colors = [
        "cyan",
        "magenta",
        "yellow",
        "green",
        "blue",
        "bright_cyan",
        "bright_magenta",
        "bright_yellow",
        "bright_green",
        "bright_blue",
    ]

    # Sort all unique IPs to ensure stable color assignment
    color_map = {
        ip: safe_colors[i % len(safe_colors)]
        for i, ip in enumerate(sorted(list(all_ips)))
    }

    for server, result in data.items():
        if error := result.get("error"):
            table.add_row(server, f"[red]{error}[/red]")
        else:
            ip_text = Text()
            # Sort the IPs for each resolver to ensure consistent display order.
            # The `append` method with a `style` argument is the correct way to add styled text.
            for ip in sorted(result.get("ips", [])):
                color = color_map.get(ip,
                                      "white")
                ip_text.append(f"{ip}\n", style=color)
            table.add_row(server, ip_text)

    table.caption = f"Checked across {len(data)} resolvers."
    return table


@console_display_handler("Security Audit")
def display_security_audit(data: dict, quiet: bool = False):
    """Creates a rich Table of Security Audit results."""
    table = Table(
        title="Security Audit",
        box=box.ROUNDED,
        show_header=True,
        header_style=None,
        show_edge=True
    )
    table.add_column("Check", style="bold", width=20)
    table.add_column("Severity", width=12)
    table.add_column("Recommendation", max_width=60)

    # A mapping of status to color and icon for visual clarity
    STATUS_MAP = {
        "Critical": {"color": "bold red", "icon": "🚨"},
        "High": {"color": "red", "icon": "✗"},
        "Medium": {"color": "yellow", "icon": "!"},
        "Low": {"color": "cyan", "icon": "•"},
    }

    findings = data.get("findings", [])

    if not findings:
        table.add_row("[green]All checks passed[/green]", "", "")
        return table

    for finding in findings:
        check_name = finding.get("finding", "Unknown Check")
        severity = finding.get("severity", "Unknown")
        recommendation = finding.get("recommendation", "N/A")

        style = STATUS_MAP.get(severity, {"color": "dim", "icon": "?"})
        table.add_row(check_name, f"{style['icon']} [{style['color']}]{severity}[/{style['color']}]", recommendation)

    return table


@console_display_handler("Technology Detection")
def display_technology_info(data: dict, quiet: bool = False):
    """Creates a rich Panel of Technology Detection results."""
    tree = Tree(f"[bold]Server:[/bold] {data.get('server', 'N/A')}")

    tech = data.get("technologies")
    if tech:
        tech_str = ", ".join(tech)
        tree.add(f"[bold]Technologies:[/bold] {tech_str}")

    headers_data = data.get("headers")
    if isinstance(headers_data, dict):
        sec_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
        ]
        header_tree = tree.add("[bold]Security Headers:[/bold]")
        for h in sec_headers:
            if h in headers_data:
                header_tree.add(f"[green]✓ {h}[/green]: {headers_data[h]}")
            else:
                header_tree.add(f"[red]✗ {h}[/red]: Not Found")

    return Panel(tree, title="Technology Detection", box=box.ROUNDED)


@console_display_handler("OSINT Enrichment")
def display_osint_results(data: dict, quiet: bool = False):
    """Creates a rich Tree of OSINT results."""
    tree = Tree("[bold]OSINT Enrichment[/bold]")

    subdomains = data.get("subdomains", [])
    if subdomains:
        sub_tree = tree.add(f"Passive Subdomains ({len(subdomains)} found)")
        for s in subdomains:
            sub_tree.add(f"[green]{s}[/green]")
    else:
        tree.add("[dim]No passive subdomains found.[/dim]")

    passive_dns = data.get("passive_dns", [])
    if passive_dns:
        pdns_tree = tree.add(f"Passive DNS Records ({len(passive_dns)} found)")
        for r in passive_dns:
            pdns_tree.add(
                f"{r.get('hostname')} -> {r.get('ip')} [dim](Last: {r.get('last_seen')})[/dim]"
            )
    else:
        tree.add("[dim]No passive DNS records found.[/dim]")

    return tree


@console_display_handler("SSL/TLS Certificate Analysis")
def display_ssl_info(data: dict, quiet: bool = False):
    """Creates a rich Panel of SSL/TLS Certificate analysis."""
    tree = Tree(f"[bold]Subject:[/bold] {data.get('subject', 'N/A')}")
    tree.add(f"[bold]Issuer:[/bold] {data.get('issuer', 'N/A')}")

    # Validity
    valid_from_ts = data.get("valid_from")
    valid_until_ts = data.get("valid_until")
    now = datetime.datetime.now().timestamp()

    if valid_from_ts and valid_until_ts:
        valid_from_dt = datetime.datetime.fromtimestamp(valid_from_ts).strftime(
            "%Y-%m-%d"
        )
        valid_until_dt = datetime.datetime.fromtimestamp(valid_until_ts).strftime(
            "%Y-%m-%d"
        )

        if now > valid_until_ts:
            validity_str = f"[red]Expired on {valid_until_dt}[/red]"
        elif now < valid_from_ts:
            validity_str = f"[yellow]Not yet valid (starts {valid_from_dt})[/yellow]"
        else:
            validity_str = (
                f"[green]Valid from {valid_from_dt} to {valid_until_dt}[/green]"
            )
        tree.add(f"[bold]Validity:[/bold] {validity_str}")

    # SANs
    sans = data.get("sans", [])
    if sans:
        sans_tree = tree.add(f"Subject Alternative Names ({len(sans)} found)")
        for s in sans:
            sans_tree.add(f"[green]{s}[/green]")

    # Connection Info
    tree.add(f"[bold]TLS Version:[/bold] {data.get('tls_version', 'N/A')}")

    return Panel(tree, title="SSL/TLS Certificate Analysis", box=box.ROUNDED)


@console_display_handler("Mail Server (SMTP) Analysis")
def display_smtp_info(data: dict, quiet: bool = False):
    """Creates a rich Panel of Mail Server (SMTP) analysis."""
    tree = Tree("[bold]SMTP Server Analysis[/bold]")
    for server, info in data.items():
        if isinstance(info, dict):
            if info.get("error"):
                tree.add(f"✗ [red]{server}[/red]: {info['error']}")
                continue
            node = tree.add(f"✓ [green]{server}[/green]")
            node.add(f"Banner: [dim]{info.get('banner', 'N/A')}[/dim]")

            starttls_status = info.get("starttls", "Unknown")
            color = "green" if starttls_status == "Supported" else "yellow"
            node.add(f"STARTTLS: [{color}]{starttls_status}[/{color}]")

            cert_info = info.get("certificate")
            if cert_info:
                cert_tree = node.add("[bold]Certificate Info[/bold]")
                cert_tree.add(f"Subject: {cert_info.get('subject', 'N/A')}")

                valid_until_ts = cert_info.get("valid_until")
                if valid_until_ts:
                    now = datetime.datetime.now().timestamp()
                    valid_until_dt = datetime.datetime.fromtimestamp(
                        valid_until_ts
                    ).strftime("%Y-%m-%d")
                    if now > valid_until_ts:
                        cert_tree.add(
                            f"Validity: [red]Expired on {valid_until_dt}[/red]"
                        )
                    else:
                        cert_tree.add(
                            f"Validity: [green]Valid until {valid_until_dt}[/green]"
                        )
        else:
            tree.add(f"✗ [red]{server}[/red]: Error - {str(info)}")

    return Panel(tree, title="Mail Server (SMTP) Analysis", box=box.ROUNDED)


@console_display_handler("IP Reputation Analysis (AbuseIPDB)")
def display_reputation_info(data: dict, quiet: bool = False):
    """Creates a rich Panel of IP Reputation analysis."""
    tree = Tree("[bold]IP Reputation Analysis (AbuseIPDB)[/bold]")
    for ip, info in data.items():
        if isinstance(info, dict):
            if info.get("error"):
                tree.add(f"✗ [red]{ip}[/red]: {info['error']}")
                continue

            score = info.get("abuseConfidenceScore", 0)
            if score > 50:
                color = "red"
            elif score > 0:
                color = "yellow"
            else:
                color = "green"

            node = tree.add(f"✓ [{color}]{ip}[/{color}]")
            node.add(f"Abuse Score: [{color}]{score}[/{color}]")
            node.add(f"Total Reports: {info.get('totalReports', 0)}")

            if info.get("lastReportedAt"):
                last_reported = datetime.datetime.fromisoformat(
                    info["lastReportedAt"].replace("Z", "+00:00")
                ).strftime("%Y-%m-%d")
                node.add(f"Last Reported: {last_reported}")
        else:
            # Handle case where info is not a dict (e.g., an error string)
            tree.add(f"✗ [red]{ip}[/red]: Error - {str(info)}")

    return Panel(tree, title="IP Reputation Analysis (AbuseIPDB)", box=box.ROUNDED)


@console_display_handler("Content & Favicon Hashes")
def display_content_hash_info(data: dict, quiet: bool = False):
    """Creates a rich Panel of Favicon and Content Hash results."""
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column("Key", style="bold cyan", no_wrap=True, width=25)
    table.add_column("Value")

    if data.get("favicon_murmur32_hash"):
        table.add_row("Favicon Murmur32 Hash:", data["favicon_murmur32_hash"])
    if data.get("page_sha256_hash"):
        table.add_row("Page Content SHA256:", data["page_sha256_hash"])

    return Panel(table, title="Content & Favicon Hashes", box=box.ROUNDED, expand=False)


@console_display_handler("Certificate Transparency Log Analysis")
def display_ct_logs(data: dict, quiet: bool = False):
    """Creates a rich Tree of Certificate Transparency Log results."""
    subdomains = data.get("subdomains", [])
    tree = Tree(
        f"[bold]Certificate Transparency Log Analysis ({len(subdomains)} found)[/bold]"
    )

    if subdomains:
        for s in subdomains:
            tree.add(f"[green]{s}[/green]")
    else:
        tree.add("[dim]No subdomains found in CT logs.[/dim]")

    return tree


@console_display_handler("WAF Detection")
def display_waf_detection(data: dict, quiet: bool = False):
    """Creates a rich Panel of WAF Detection results."""
    detected_wafs = data.get("detected_wafs", [])
    details = data.get("details", {})

    if detected_wafs:
        color = "green"
        waf_list_str = ", ".join([f"[bold]{waf}[/bold]" for waf in detected_wafs])
        reasons = "; ".join(
            [details.get(waf, "") for waf in detected_wafs if waf in details]
        )
        message = f"Identified: {waf_list_str}. [dim]({reasons})[/dim]"
    else:
        color = "dim"
        message = "No WAF identified from response headers."
    return Panel(
        f"[{color}]{message}[/{color}]", title="WAF Detection", box=box.ROUNDED
    )


@console_display_handler("DANE/TLSA Record Analysis")
def display_dane_analysis(data: dict, quiet: bool = False):
    """Creates a rich Panel of DANE/TLSA analysis."""
    status = data.get("status", "Not Found")
    if status == "Present":
        color = "green"
        tree = Tree(
            f"✓ [{color}]DANE/TLSA records found for _443._tcp (HTTPS)[/{color}]"
        )
        for record in data.get("records", []):
            tree.add(f"[dim]{record}[/dim]")
    else:
        color = "dim"
        tree = Tree(
            f"[{color}]No DANE/TLSA records found for _443._tcp (HTTPS)[/{color}]"
        )

    return Panel(tree, title="DANE/TLSA Record Analysis", box=box.ROUNDED)


@console_display_handler("Scan Summary")
def display_summary(data: dict, quiet: bool = False):
    """Creates a rich Table for the high-level summary of findings."""
    table = Table(title="Scan Summary", box=box.ROUNDED, show_header=False)
    table.add_column("Module", style="bold cyan")
    table.add_column("Finding")

    # Zone Transfer
    axfr_summary = data.get("zone_info", {}).get("summary", "N/A")
    axfr_color = "bold red" if "Vulnerable" in axfr_summary else "green"
    table.add_row("Zone Transfer", f"[{axfr_color}]{axfr_summary}[/{axfr_color}]")

    # SPF
    spf_policy = data.get("email_security", {}).get("spf", {}).get("all_policy",
                                                                   "Not Found")
    spf_color = (
        "red"
        if spf_policy in ["?all", "Not Found"]
        else "yellow" if spf_policy == "~all" else "green"
    )
    table.add_row("SPF Policy", f"[{spf_color}]{spf_policy}[/{spf_color}]")

    # DMARC
    dmarc_policy = data.get("email_security", {}).get("dmarc",
                                                      {}).get("p", "Not Found")
    dmarc_color = "red" if dmarc_policy in ["none", "Not Found", "Error"] else "green"
    table.add_row("DMARC Policy", f"[{dmarc_color}]{dmarc_policy}[/{dmarc_color}]")

    # Security Audit
    audit_data = data.get("security", {})
    if isinstance(audit_data, dict) and "error" not in audit_data:
        weak_checks = [check for check, info in audit_data.items() if
                       info.get("status") in ("Weak", "Vulnerable")]
        if weak_checks:
            table.add_row(
                "Security Audit",
                f"[red]Found {len(weak_checks)} issues[/red] ({', '.join(weak_checks)})"
            )
        else:
            table.add_row("Security Audit", "[green]All checks passed[/green]")
    else:
        table.add_row("Security Audit", "[dim]No audit data[/dim]")
    return table


@console_display_handler("🚨 Critical Findings")
def display_critical_findings(data: dict, quiet: bool = False):
    """Creates a rich Panel for the most critical findings."""
    critical_findings = []

    if "Vulnerable" in data.get("zone_info", {}).get("summary", ""):
        critical_findings.append(
            "Zone Transfer Successful (AXFR): Domain is vulnerable to full zone "
            "enumeration."
        )

    # Subdomain Takeover
    vulnerable_takeovers = data.get("takeover_info", {}).get("vulnerable", [])
    if vulnerable_takeovers:
        critical_findings.append(f"Subdomain Takeover: Found {len(vulnerable_takeovers)} "
                                 "potentially vulnerable subdomains."
        )

    ssl_info = data.get("ssl_info", {})
    if ssl_info.get("valid_until") and (
        datetime.datetime.now().timestamp() > ssl_info["valid_until"]
    ):
        critical_findings.append(
            "Expired SSL/TLS Certificate: The main web server's certificate has "
            "expired."
        )

    # High IP Reputation Abuse Score
    reputation_info = data.get("reputation_info", {})
    high_risk_ips = [
        ip
        for ip, info in reputation_info.items()
        if isinstance(info, dict) and info.get("abuseConfidenceScore", 0) > 75
    ]
    if high_risk_ips:
        critical_findings.append(
            f"High-Risk IP Reputation: {len(high_risk_ips)} IP(s) have a high abuse "
            f"score ({', '.join(high_risk_ips)})."
        )

    if not critical_findings:
        return None  # Return nothing if there are no findings

    text = Text()
    for finding in critical_findings:
        text.append("• ", style="bold red")
        text.append(f"{finding}\n")

    return Panel(
        text,
        title="[bold red]🚨 Critical Findings[/bold red]",
        box=box.ROUNDED,
        border_style="red",
    )


@console_display_handler("HTTP Security Headers Analysis")
def display_http_headers(data: dict, quiet: bool = False):
    """Creates a rich Table of HTTP Security Headers analysis."""
    final_url = data.get("final_url", "N/A")
    title = (f"HTTP Security Headers Analysis\n[dim]Final URL: {final_url}[/dim]")
    table = Table(title=title, box=box.ROUNDED, show_header=True,
                  header_style=None,
    )
    table.add_column("Header", style="bold", width=28)
    table.add_column("Status", width=10)
    table.add_column("Value / Details", max_width=60)

    analysis = data.get("analysis", {})
    for header, info in analysis.items():
        status = info.get("status", "Unknown")
        value = info.get("value", "")

        if status in ("Strong", "Present"):
            color = "green"
        elif status in ("Weak", "Moderate"):
            color = "yellow"
        else:  # Missing, Invalid
            color = "red"

        table.add_row(header, f"[{color}]{status}[/{color}]", value)

    recommendations = data.get("recommendations", [])
    if recommendations:
        rec_text = "\n".join([f"• {rec}" for rec in recommendations])
        table.caption = Text(rec_text,
                             style="yellow")

    return table


@console_display_handler("Open Port Scan")
def display_port_scan(data: dict, quiet: bool = False):
    """Creates a rich Table of Open Port Scan results."""
    table = Table(
        title="Open Port Scan", box=box.ROUNDED, show_header=True, header_style=None
    )
    table.add_column("IP Address", style="bold", width=20)
    table.add_column("Open Ports")

    if not data:
        return Panel(
            "[dim]No port scan data to display.[/dim]",
            title="Open Port Scan",
            box=box.ROUNDED,
        )

    for ip, ports in data.items():
        ports_str = ", ".join(map(str, ports))
        table.add_row(ip, f"[green]{ports_str}[/green]")
    return table


@console_display_handler("Subdomain Takeover")
def display_subdomain_takeover(data: dict, quiet: bool = False):
    """Creates a rich Panel of Subdomain Takeover results."""
    vulnerable = data.get("vulnerable", [])

    if not vulnerable:
        panel = Panel(
            "[green]✓ No potential subdomain takeovers found.[/green]",  # noqa: E501
            title="Subdomain Takeover",
            box=box.ROUNDED,
        )  # noqa: E124
    else:
        tree = Tree(
            f"[bold red]✗ Found {len(vulnerable)} potential subdomain takeovers![/bold red]"
        )
        for item in vulnerable:
            node = tree.add(f"[yellow]{item['subdomain']}[/yellow]")
            node.add(f"Service: [bold]{item['service']}[/bold]")
            node.add(f"CNAME Target: [dim]{item['cname_target']}[/dim]")
        panel = Panel(
            tree, title="Subdomain Takeover", box=box.ROUNDED, border_style="red"  # noqa: E124
        )

    return panel


@console_display_handler("Cloud Service Enumeration")
def display_cloud_enum(data: dict, quiet: bool = False):
    """Creates a rich Panel of Cloud Enumeration results."""
    s3_buckets = data.get("s3_buckets", [])
    azure_blobs = data.get("azure_blobs", [])

    if not s3_buckets and not azure_blobs:  # noqa: W503
        panel = Panel(
            "[dim]No public S3 buckets or Azure blobs found based on "
            "common permutations.[/dim]",
            title="Cloud Service Enumeration",
            box=box.ROUNDED,
        )
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
            azure_tree = tree.add(
                f"Discovered Azure Blob Containers ({len(azure_blobs)}):"
            )
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

    return panel


@console_display_handler("DNS Blocklist (DNSBL) Check")
def display_dnsbl_check(data: dict, quiet: bool = False):
    """Creates a rich Panel of DNSBL check results."""
    listed_ips = data.get("listed_ips", [])

    if not listed_ips:
        panel = Panel(
            "[green]✓ No discovered IPs were found on common DNS blocklists.[/green]",  # noqa: E501
            title="DNS Blocklist (DNSBL) Check",
            box=box.ROUNDED,
        )
    else:
        tree = Tree(
            f"[bold red]✗ Found {len(listed_ips)} IP(s) on DNS blocklists![/bold red]"
        )
        for item in listed_ips:
            node = tree.add(f"[yellow]{item['ip']}[/yellow]")
            node.add(f"Listed on: [dim]{', '.join(item.get('listed_on', []))}[/dim]")
        panel = Panel(
            tree,
            title="DNS Blocklist (DNSBL) Check",  # noqa: E124
            box=box.ROUNDED,
            border_style="red",
        )

    return panel
