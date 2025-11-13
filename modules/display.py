#!/usr/bin/env python3
"""
Zone-Poker - Display Module
Handles all console output formatting using the 'rich' library.
"""
from typing import Dict, Any, List, Optional
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich import box
import datetime


# --- Generic Table Helper ---


def _create_generic_table(
    data_list: List[Dict[str, Any]],
    title: str,
    columns: Dict[str, Dict[str, Any]],
    caption_noun: str = "items",
    empty_message: str = "No data to display.",
) -> Table:
    """
    Creates a rich Table from a list of dictionaries in a data-driven way.

    Args:
        data_list: The list of data dictionaries to display.
        title: The title of the table.
        columns: A dictionary defining the columns. Keys are the keys in the data dict,
                 and values are dicts for Rich table.add_column arguments.
        caption_noun: The noun to use in the table caption (e.g., "records").
        empty_message: The message to display if data_list is empty.

    Returns:
        A rich Table object.
    """
    table = Table(title=title, show_header=True, header_style="bold magenta")
    for col_config in columns.values():
        table.add_column(**col_config)

    if not data_list:
        table.add_row(empty_message)
        table.caption = f"Total: 0 {caption_noun} found"
        return table

    for item in data_list:
        row = [str(item.get(key, "")) for key in columns.keys()]
        table.add_row(*row)

    plural = "s" if len(data_list) != 1 else ""
    table.caption = f"Total: {len(data_list)} {caption_noun}{plural} found"
    return table


# --- Display Functions ---


def display_dns_records_table(
    records_info: Dict[str, Any], quiet: bool, **kwargs
) -> Optional[Table]:
    """Displays all found DNS records in a single, consolidated table."""
    if quiet:
        return None

    all_records: List[Dict[str, Any]] = []
    for r_type, records in records_info.items():
        for record in records:
            record["record_type"] = r_type
            all_records.append(record)

    columns = {
        "record_type": {"header": "Type", "style": "cyan", "no_wrap": True},
        "name": {"header": "Name", "style": "magenta"},
        "value": {"header": "Value", "style": "green"},
        "ttl": {"header": "TTL", "style": "yellow"},
        "priority": {"header": "Priority", "style": "blue"},
    }

    return _create_generic_table(
        all_records,
        "DNS Records Discovery",
        columns,
        caption_noun="record",
        empty_message="No DNS records found.",
    )


def display_ptr_lookups(
    ptr_info: Dict[str, Any], quiet: bool, **kwargs
) -> Optional[Table]:
    """Displays PTR lookup results using the generic table builder."""
    if quiet or not ptr_info.get("ptr_records"):
        return None

    columns = {
        "ip": {"header": "IP Address", "style": "cyan"},
        "hostname": {"header": "Hostname", "style": "green"},
    }
    return _create_generic_table(
        ptr_info["ptr_records"],
        "Reverse DNS (PTR) Lookups",
        columns,
        caption_noun="lookup",
    )


def display_security_audit(
    security_info: Dict[str, Any], quiet: bool, **kwargs
) -> Optional[Panel]:
    """Displays security audit findings in a Tree structure."""
    if quiet:
        return None

    findings = security_info.get("findings", [])
    if not findings:
        return Panel(
            "[bold green]✓ All security checks passed.[/bold green]",
            title="[bold]Security Audit[/bold]",
            border_style="green",
        )

    tree = Tree("Findings", guide_style="bold bright_blue")
    severity_map = {
        "Critical": "[bold red]",
        "High": "[red]",
        "Medium": "[yellow]",
        "Low": "[cyan]",
    }

    for severity_name, style in severity_map.items():
        severity_findings = [f for f in findings if f["severity"] == severity_name]
        if severity_findings:
            branch = tree.add(f"{style}{severity_name} Severity Findings")
            for finding in severity_findings:
                finding_branch = branch.add(f"[bold]{finding['finding']}[/bold]")
                finding_branch.add(
                    f"[dim]Recommendation:[/dim] {finding['recommendation']}"
                )

    return Panel(tree, title="[bold]Security Audit[/bold]", border_style="red")


def display_subdomain_takeover(
    takeover_info: Dict[str, Any], quiet: bool, **kwargs
) -> Optional[Panel]:
    """Displays subdomain takeover results."""
    if quiet:
        return None

    vulnerable = takeover_info.get("vulnerable", [])
    if not vulnerable:
        return Panel(
            "[green]No potential subdomain takeovers found.[/green]",
            title="[bold]Subdomain Takeover Scan[/bold]",
            border_style="green",
        )

    columns = {
        "subdomain": {"header": "Subdomain", "style": "red"},
        "service": {"header": "Service", "style": "yellow"},
        "cname_target": {"header": "CNAME Target", "style": "cyan"},
    }
    table = _create_generic_table(
        vulnerable,
        "",
        columns,
        caption_noun="potential takeover",
    )

    return Panel(
        table,
        title="[bold red]Subdomain Takeover Scan[/bold red]",
        border_style="red",
    )


def display_summary(all_data: Dict[str, Any], quiet: bool, **kwargs) -> Optional[Table]:
    """Displays a summary table of key findings."""
    if quiet:
        return None

    table = Table(title="[bold]Scan Summary[/bold]", show_header=False)
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Result", style="white")

    # Data-driven summary checks
    SUMMARY_CHECKS = [
        {
            "label": "Zone Transfer",
            "data_key": "zone_info",
            "value_path": "summary",
            "styles": {"Vulnerable": "[bold red]"},
        },
        {
            "label": "DNSSEC",
            "data_key": "nsinfo_info",
            "value_path": "dnssec",
            "styles": {"Not Enabled": "[yellow]"},
        },
        {
            "label": "Email Security",
            "func": lambda d: (
                "Secure"
                if d.get("mail_info", {}).get("dmarc", {}).get("p")
                in ("reject", "quarantine")
                and d.get("mail_info", {}).get("spf", {}).get("all_policy")
                in ("-all", "~all")
                else "Misconfigured"
            ),
            "styles": {"Misconfigured": "[yellow]"},
        },
        {
            "label": "Security Audit",
            "func": lambda d: (
                f"Found {len(d.get('security_info', {}).get('findings', []))} issues"
                if d.get("security_info", {}).get("findings")
                else "[green]✓ Passed[/green]"
            ),
            "styles": {"Found": "[red]"},
        },
    ]

    for check in SUMMARY_CHECKS:
        result_text = "Not Scanned"
        if "func" in check:
            result_text = check["func"](all_data)
        elif (data := all_data.get(check["data_key"])) and (
            val := data.get(check["value_path"])
        ):
            result_text = str(val)

        # Apply styling
        for keyword, style in check.get("styles", {}).items():
            if keyword in result_text:
                result_text = f"{style}{result_text}[/]"
                break
        table.add_row(check["label"], result_text)

    return table


def display_axfr_results(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays Zone Transfer (AXFR) results in a tree."""
    if quiet:
        return None

    summary = data.get("summary", data.get("status", "No data."))
    style = "bold red" if "Vulnerable" in summary else "bold green"

    tree = Tree(f"[bold]Zone Transfer (AXFR): [/bold][{style}]{summary}[/{style}]")

    servers = data.get("servers", {})
    if not servers:
        tree.add("[dim]No nameservers were checked.[/dim]")

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

    return Panel(tree, title="[bold]Zone Transfer (AXFR)[/bold]")


def display_email_security(data: dict, quiet: bool, **kwargs) -> Optional[Table]:
    """Displays Email Security results in a table."""
    if quiet:
        return None

    table = Table(
        title="[bold]Email Security Analysis[/bold]", show_header=False, box=None
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


def display_whois_info(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays WHOIS data in a rich panel."""
    if quiet or not isinstance(data, dict):
        return None

    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column("Key", style="bold cyan", no_wrap=True, width=18)
    table.add_column("Value")

    EXCLUDE_KEYS = {"error"}
    for key, value in data.items():
        if key in EXCLUDE_KEYS or not value:
            continue

        value_str = str(value)
        if "date" in key and isinstance(value, str):
            try:
                dt = datetime.datetime.fromisoformat(value)
                value_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                pass

        table.add_row(f"{key.replace('_', ' ').title()}:", value_str)

    return Panel(table, title="[bold]WHOIS Information[/bold]", expand=False)


def display_nameserver_analysis(data: dict, quiet: bool, **kwargs) -> Optional[Table]:
    """Displays Nameserver Analysis in a table."""
    if quiet:
        return None

    dnssec_status = data.get("dnssec", "Unknown")
    color = "green" if "Enabled" in dnssec_status else "red"
    title = f"Nameserver Analysis (DNSSEC: [{color}]{dnssec_status}[/{color}])"

    table = Table(title=title)
    table.add_column("Nameserver", style="bold")
    table.add_column("IP Address(es)")
    table.add_column("ASN Description")

    for ns, info in data.items():
        if ns == "dnssec":
            continue

        if isinstance(info, dict):
            if "error" in info:
                table.add_row(ns, f"[red]{info['error']}[/red]", "")
            else:
                ip_list = info.get("ips", [])
                ip_str = "\n".join(ip_list) if ip_list else "N/A"
                table.add_row(ns, ip_str, info.get("asn_description", "N/A"))

    return table


def display_propagation(data: dict, quiet: bool, **kwargs) -> Optional[Table]:
    """Displays DNS propagation check results in a table."""
    if quiet:
        return None

    table = Table(title="[bold]DNS Propagation Check[/bold]")
    table.add_column("Resolver", style="cyan")
    table.add_column("IP Address(es)", style="green")

    all_ip_sets = []
    for resolver, result in data.items():
        if isinstance(result, dict):
            ips = result.get("ips")
            error = result.get("error")

            if error:
                ip_str = f"[red]({error})[/red]"
            elif ips:
                ip_str = ", ".join(ips)
                all_ip_sets.append(frozenset(ips))
            else:
                ip_str = "[dim]No IPs returned[/dim]"

            table.add_row(resolver, ip_str)

    # Determine if propagation is consistent
    if not all_ip_sets:
        table.caption = (
            "[yellow]Domain did not resolve on any public resolver.[/yellow]"
        )
    elif len(set(all_ip_sets)) > 1:
        table.caption = (
            "[bold red]Propagation is inconsistent across resolvers.[/bold red]"
        )
    else:
        table.caption = "[green]Propagation appears consistent.[/green]"

    return table


def display_critical_findings(
    all_data: Dict[str, Any], quiet: bool, **kwargs
) -> Optional[Panel]:
    """
    Displays a summary of critical and high-severity findings.
    """
    if quiet:
        return None

    # The 'critical_findings' module aggregates these from the main security audit
    critical_info = all_data.get("critical_findings_info", {})
    findings = critical_info.get("critical_findings", [])

    if not findings:
        return None  # Don't display anything if there are no critical findings

    tree = Tree(
        f"[bold red]✗ Found {len(findings)} Critical/High Severity Issues[/bold red]"
    )
    for finding in findings:
        tree.add(f"[yellow]• {finding}[/yellow]")

    return Panel(tree, title="[bold]Critical Findings[/bold]", border_style="red")


def display_technology_info(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays detected web technologies in a panel."""
    if quiet:
        return None

    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column("Key", style="bold cyan", no_wrap=True, width=15)
    table.add_column("Value")

    if server := data.get("server"):
        table.add_row("Server:", server)

    if techs := data.get("technologies"):
        table.add_row("Technologies:", ", ".join(techs))

    if table.row_count == 0:
        return Panel(
            "[dim]No technology information found.[/dim]",
            title="[bold]Technology Detection[/bold]",
        )

    return Panel(table, title="[bold]Technology Detection[/bold]")


def display_osint_results(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays OSINT enrichment results in a tree."""
    if quiet:
        return None

    subdomains = data.get("subdomains", [])
    passive_dns = data.get("passive_dns", [])

    if not subdomains and not passive_dns:
        return Panel(
            "[dim]No OSINT data found from external sources.[/dim]",
            title="[bold]OSINT Enrichment[/bold]",
        )

    tree = Tree("OSINT Findings")

    if subdomains:
        sub_branch = tree.add(f"Found {len(subdomains)} subdomains")
        for sub in subdomains:
            sub_branch.add(f"[green]{sub}[/green]")

    if passive_dns:
        dns_branch = tree.add(f"Found {len(passive_dns)} passive DNS records")
        for record in passive_dns:
            dns_branch.add(
                f"[cyan]{record.get('hostname')}[/cyan] -> [yellow]{record.get('ip')}[/yellow] (Last seen: {record.get('last_seen')})"
            )

    return Panel(tree, title="[bold]OSINT Enrichment[/bold]")


def display_ssl_info(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays SSL/TLS certificate analysis."""
    if quiet:
        return None

    if error := data.get("error"):
        return Panel(
            f"[dim]{error}[/dim]",
            title="[bold]SSL/TLS Analysis[/bold]",
            border_style="red",
        )

    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column("Key", style="bold cyan", no_wrap=True, width=15)
    table.add_column("Value")

    table.add_row("Subject:", data.get("subject", "N/A"))
    table.add_row("Issuer:", data.get("issuer", "N/A"))

    if valid_from := data.get("valid_from"):
        from_date = datetime.datetime.fromtimestamp(valid_from).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        table.add_row("Valid From:", from_date)

    if valid_until := data.get("valid_until"):
        until_date = datetime.datetime.fromtimestamp(valid_until).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        table.add_row("Valid Until:", until_date)

    table.add_row("TLS Version:", data.get("tls_version", "N/A"))

    if sans := data.get("sans"):
        table.add_row("SANs:", ", ".join(sans[:5]) + ("..." if len(sans) > 5 else ""))

    return Panel(table, title="[bold]SSL/TLS Certificate Analysis[/bold]")


def display_smtp_info(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays SMTP server analysis results."""
    if quiet:
        return None

    if not data:
        return Panel(
            "[dim]No SMTP servers were analyzed.[/dim]",
            title="[bold]Mail Server (SMTP) Analysis[/bold]",
        )

    tree = Tree("SMTP Servers")
    for server, info in data.items():
        if isinstance(info, dict):
            if error := info.get("error"):
                tree.add(f"✗ [red]{server}: Error - {error}[/red]")
                continue

            node = tree.add(f"✓ [green]{server}[/green]")
            node.add(f"Banner: [dim]{info.get('banner', 'N/A')}[/dim]")

            starttls = info.get("starttls", "Unknown")
            color = "green" if starttls == "Supported" else "red"
            node.add(f"STARTTLS: [{color}]{starttls}[/{color}]")

            if cert_info := info.get("certificate"):
                cert_node = node.add("Certificate")
                cert_node.add(f"Subject: {cert_info.get('subject', 'N/A')}")
                if valid_until := cert_info.get("valid_until"):
                    valid_until_str = datetime.datetime.fromtimestamp(
                        valid_until
                    ).strftime("%Y-%m-%d")
                    cert_node.add(f"Valid Until: {valid_until_str}")

    return Panel(tree, title="[bold]Mail Server (SMTP) Analysis[/bold]")


def display_reputation_info(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays IP reputation analysis from AbuseIPDB."""
    if quiet or not data:
        return None

    tree = Tree("IP Reputation (AbuseIPDB)")

    has_data = False
    for ip, info in data.items():
        if isinstance(info, dict):
            has_data = True
            if error := info.get("error"):
                tree.add(f"✗ [red]{ip}: Error - {error}[/red]")
                continue

            score = info.get("abuseConfidenceScore", 0)

            color = "green"
            if score > 75:
                color = "bold red"
            elif score > 25:
                color = "yellow"

            node = tree.add(f"✓ [{color}]{ip}[/{color}] - Score: {score}")
            node.add(f"Total Reports: {info.get('totalReports', 0)}")
            if last_reported := info.get("lastReportedAt"):
                last_reported_str = datetime.datetime.fromisoformat(
                    last_reported.replace("Z", "+00:00")
                ).strftime("%Y-%m-%d")
                node.add(f"Last Reported: {last_reported_str}")

    if not has_data:
        return Panel(
            "[dim]No IP reputation data to display.[/dim]",
            title="[bold]IP Reputation Analysis[/bold]",
        )

    return Panel(tree, title="[bold]IP Reputation Analysis[/bold]")


def display_content_hash_info(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays content and favicon hash information."""
    if quiet:
        return None

    if not data or not any(data.values()):
        return Panel(
            "[dim]No content hashes were generated.[/dim]",
            title="[bold]Content & Favicon Hashes[/bold]",
        )

    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column("Key", style="bold cyan", no_wrap=True, width=25)
    table.add_column("Value")

    if favicon_hash := data.get("favicon_murmur32_hash"):
        table.add_row("Favicon Murmur32 Hash:", favicon_hash)

    if page_hash := data.get("page_sha256_hash"):
        table.add_row("Page Content SHA256:", page_hash)

    return Panel(table, title="[bold]Content & Favicon Hashes[/bold]")


def display_ct_logs(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays Certificate Transparency log results."""
    if quiet:
        return None

    subdomains = data.get("subdomains", [])

    if not subdomains:
        return Panel(
            "[dim]No subdomains found in Certificate Transparency logs.[/dim]",
            title="[bold]CT Log Search[/bold]",
        )

    tree = Tree(f"Found {len(subdomains)} subdomains in CT logs")
    for sub in subdomains:
        tree.add(f"[green]{sub}[/green]")

    return Panel(tree, title="[bold]Certificate Transparency Log Search[/bold]")


def display_waf_detection(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays Web Application Firewall (WAF) detection results."""
    if quiet:
        return None

    detected_wafs = data.get("detected_wafs", [])
    details = data.get("details", {})

    if not detected_wafs:
        return Panel(
            "[green]✓ No Web Application Firewall identified.[/green]",
            title="[bold]WAF Detection[/bold]",
            border_style="green",
        )

    tree = Tree(f"[bold red]✗ Found {len(detected_wafs)} potential WAF(s)[/bold red]")
    for waf in detected_wafs:
        tree.add(f"[yellow]{waf}[/yellow]: {details.get(waf, 'No specific details.')}")

    return Panel(tree, title="[bold]WAF Detection[/bold]", border_style="red")


def display_dane_analysis(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays DANE/TLSA record analysis results."""
    if quiet:
        return None

    status = data.get("status", "Not Found")
    records = data.get("records", [])

    color = "green" if "Found" in status else "dim"
    if "Error" in status:
        color = "red"

    tree = Tree(f"Status for _443._tcp (HTTPS): [{color}]{status}[/{color}]")

    if records:
        record_branch = tree.add("Records")
        for record in records:
            record_branch.add(f"[cyan]{record}[/cyan]")
    elif "Not Found" in status:
        tree.add("[dim]No DANE records published for HTTPS.[/dim]")

    return Panel(tree, title="[bold]DANE/TLSA Record Analysis[/bold]")


def display_http_headers(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays HTTP security header analysis."""
    if quiet:
        return None

    if error := data.get("error"):
        return Panel(
            f"[dim]{error}[/dim]",
            title="[bold]HTTP Security Headers Analysis[/bold]",
            border_style="red",
        )

    analysis = data.get("analysis", {})
    if not analysis:
        return Panel(
            "[dim]No header analysis data found.[/dim]",
            title="[bold]HTTP Security Headers Analysis[/bold]",
        )

    table = Table(show_header=True, header_style="bold")
    table.add_column("Header", style="cyan")
    table.add_column("Status")
    table.add_column("Value / Details")

    status_colors = {
        "Missing": "red",
        "Weak": "yellow",
        "Invalid": "red",
        "Disabled": "dim",
        "Present": "green",
        "Strong": "bold green",
    }

    for header, details in analysis.items():
        status = details.get("status", "Unknown")
        color = status_colors.get(status, "white")
        value = details.get("value", "")
        table.add_row(header, f"[{color}]{status}[/{color}]", value)

    if recommendations := data.get("recommendations"):
        table.caption = "\n".join(f"• {rec}" for rec in recommendations)

    return Panel(table, title="[bold]HTTP Security Headers Analysis[/bold]")


def display_port_scan(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays open port scan results."""
    if quiet:
        return None

    scan_results = data.get("scan_results", [])
    if not scan_results:
        return Panel(
            "[dim]No open ports found among common ports.[/dim]",
            title="[bold]Open Port Scan[/bold]",
        )

    # Pre-process data to format the list of ports as a string
    processed_data = []
    for item in scan_results:
        new_item = item.copy()
        new_item["ports"] = ", ".join(map(str, item.get("ports", [])))
        processed_data.append(new_item)

    columns = {
        "ip": {"header": "IP Address", "style": "cyan"},
        "ports": {"header": "Open Ports", "style": "green"},
    }
    table = _create_generic_table(processed_data, "", columns, "IP")

    return Panel(table, title="[bold]Open Port Scan[/bold]")


def display_cloud_enum(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays Cloud Enumeration results."""
    if quiet or not isinstance(data, dict):
        return None

    s3_buckets = data.get("s3_buckets", [])
    azure_blobs = data.get("azure_blobs", [])

    if not s3_buckets and not azure_blobs:
        return Panel(
            "[dim]No public S3 or Azure Blob containers found.[/dim]",
            title="[bold]Cloud Service Enumeration[/bold]",
        )

    tree = Tree("Cloud Service Findings")

    if s3_buckets:
        s3_branch = tree.add(f"Found {len(s3_buckets)} S3 Buckets 🪣")
        for bucket in s3_buckets:
            status = bucket.get("status", "unknown")
            color = "green" if status == "public" else "yellow"
            icon = "✓" if status == "public" else "✗"
            s3_branch.add(
                f"{icon} [{color}]{bucket.get('url')}[/{color}] (Status: {status})"
            )

    if azure_blobs:
        azure_branch = tree.add(f"Found {len(azure_blobs)} Azure Blobs ☁️")
        for blob in azure_blobs:
            status = blob.get("status", "unknown")
            color = "green" if status == "public" else "yellow"
            icon = "✓" if status == "public" else "✗"
            azure_branch.add(
                f"{icon} [{color}]{blob.get('url')}[/{color}] (Status: {status})"
            )

    return Panel(tree, title="[bold]Cloud Service Enumeration[/bold]")


def display_dnsbl_check(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays DNS Blocklist (DNSBL) check results."""
    if quiet:
        return None

    listed_ips = data.get("listed_ips", [])

    if not listed_ips:
        return Panel(
            "[green]✓ No discovered IPs were found on common DNS blocklists.[/green]",
            title="[bold]DNS Blocklist (DNSBL) Check[/bold]",
            border_style="green",
        )

    tree = Tree(
        f"[bold red]✗ Found {len(listed_ips)} IP(s) on DNS blocklists![/bold red]"
    )
    for item in listed_ips:
        node = tree.add(f"[yellow]{item.get('ip', 'N/A')}[/yellow]")
        node.add(f"Listed on: [dim]{', '.join(item.get('listed_on', []))}[/dim]")

    return Panel(
        tree, title="[bold]DNS Blocklist (DNSBL) Check[/bold]", border_style="red"
    )


def display_open_redirect(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays Open Redirect scan results."""
    if quiet:
        return None

    vulnerable_urls = data.get("vulnerable_urls", [])

    if not vulnerable_urls:
        return Panel(
            "[green]✓ No potential open redirects found.[/green]",
            title="[bold]Open Redirect Scan[/bold]",
            border_style="green",
        )

    tree = Tree(
        f"[bold red]✗ Found {len(vulnerable_urls)} potential open redirects![/bold red]"
    )
    for item in vulnerable_urls:
        node = tree.add(f"URL: [yellow]{item.get('url', 'N/A')}[/yellow]")
        node.add(f"Redirects To: [dim]{item.get('redirects_to', 'N/A')}[/dim]")

    return Panel(tree, title="[bold]Open Redirect Scan[/bold]", border_style="red")


def display_security_txt(data: dict, quiet: bool, **kwargs) -> Optional[Panel]:
    """Displays security.txt analysis results in a panel."""
    if quiet:
        return None

    if not data.get("found"):
        return Panel(
            "[dim]No security.txt file found at standard locations.[/dim]",
            title="[bold]Security.txt Check[/bold]",
            box=box.ROUNDED,
            border_style="dim",
        )

    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column("Directive", style="bold cyan", no_wrap=True, width=18)
    table.add_column("Value")

    parsed_content = data.get("parsed", {})
    if not parsed_content:
        table.add_row("[dim]File was empty or could not be parsed.[/dim]", "")
    else:
        for key, value in parsed_content.items():
            # Handle directives that can appear multiple times
            if isinstance(value, list):
                value_str = "\n".join(value)
            else:
                value_str = str(value)
            table.add_row(f"{key}:", value_str)

    title = (
        f"[bold]Security.txt Check[/bold] ([green]Found at {data.get('url')}[/green])"
    )
    return Panel(table, title=title, box=box.ROUNDED, expand=False)


def display_ip_geolocation(data: dict, quiet: bool, **kwargs) -> Optional[Table]:
    """Displays IP Geolocation results in a table."""
    if quiet or not data:
        return None

    columns = {
        "ip": {"header": "IP Address", "style": "cyan"},
        "country": {"header": "Country", "style": "green"},
        "city": {"header": "City", "style": "yellow"},
        "isp": {"header": "ISP", "style": "blue"},
    }
    # The data is a dict of dicts, so we need to convert it to a list
    data_list = [{**info, "ip": ip} for ip, info in data.items()]

    return _create_generic_table(data_list, "IP Geolocation", columns, "IP")
