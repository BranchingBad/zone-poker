#!/usr/bin/env python3
"""
Zone-Poker - TXT Report Export Module
Contains all functions for formatting analysis data into a plain text report.
"""
import datetime
import logging
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# --- TXT REPORT EXPORT FUNCTIONS ---
# -----------------------------------------------------------------


def _create_report_section(
    title: str, data: Dict[str, Any], formatter: Callable[[Dict[str, Any]], List[str]]
) -> str:
    """
    A helper to create a formatted text report section with a standard header and error handling.
    """
    report = ["=" * 15 + f" {title} " + "=" * 15]
    if not isinstance(data, dict):
        report.append(
            f"  Error: Unexpected data format for {title}. "
            f"Expected dictionary, got {type(data).__name__}."
        )
        if data:
            report.append(f"  Raw data: {data}")
        return "\n".join(report)
    if not data:
        report.append("No data found for this section.")
    elif data.get("error"):
        error_msg = data["error"]
        report.append(f"  Error: {error_msg}")
        logger.debug(
            f"Skipping report section '{title}' due to pre-existing error: {error_msg}"
        )
    else:
        try:
            report.extend(formatter(data))
        except Exception as e:
            error_msg = (
                f"An unexpected error occurred in the formatter for the "
                f"'{title}' report section: {e}"
            )
            logger.error(error_msg, exc_info=True)
            report.append(
                f"  Error: Could not format data for this section due to an "
                f"unexpected error: {e}"
            )
    return "\n".join(report)


def _format_summary_txt(data: Dict[str, Any]) -> List[str]:
    """Helper to format the scan summary for the text report."""
    SUMMARY_CHECKS = [
        {
            "label": "Zone Transfer",
            "value_func": lambda d: d.get("zone_info", {}).get("summary", "N/A"),
        },
        {
            "label": "SPF Policy",
            "value_func": lambda d: d.get("mail_info", {})
            .get("spf", {})
            .get("all_policy", "Not Found"),
        },
        {
            "label": "DMARC Policy",
            "value_func": lambda d: d.get("mail_info", {})
            .get("dmarc", {})
            .get("p", "Not Found"),
        },
        {
            "label": "Security Audit",
            "value_func": lambda d: (
                f"Found {len(d.get('security_info', {}).get('findings', []))} issues"
                if d.get("security_info", {}).get("findings")
                else "All checks passed"
            ),
        },
    ]

    report = []
    for check in SUMMARY_CHECKS:
        value = "Data Missing"
        try:
            value = check["value_func"](data)
        except (KeyError, TypeError):
            # Gracefully handle cases where data is missing
            pass
        report.append(f"  {check['label']:<20}: {value}")

    return report


def export_txt_summary(data: Dict[str, Any]) -> str:
    """Formats a high-level summary for the text report."""
    return _create_report_section("Scan Summary", data, _format_summary_txt)


def _format_records_txt(data: Dict[str, List[Any]]) -> List[str]:
    """Formats DNS records for the text report."""
    report = []
    for r_type, items in data.items():
        if items:
            report.append(f"\n[{r_type}]")
            for record in items:
                value = record.get("value", "N/A")
                extra = ""
                if r_type == "MX" and "priority" in record:
                    extra = f" (Priority: {record['priority']})"
                elif r_type == "SRV":
                    extra = (
                        f" (P: {record.get('priority')} W: {record.get('weight')} "
                        f"Port: {record.get('port')})"
                    )
                elif r_type == "SOA":
                    rname = record.get("rname", "N/A")
                    serial = record.get("serial", "N/A")
                    extra = f" (RNAME: {rname}, Serial: {serial})"
                report.append(f"  - {value}{extra}")
    return report if report else ["No DNS records found."]


def export_txt_records(data: Dict[str, List[Any]]) -> str:
    """Formats DNS records for the text report."""
    return _create_report_section("DNS Records", data, _format_records_txt)


def _format_ptr_txt(data: Dict[str, str]) -> List[str]:
    ptr_records = data.get("ptr_records", [])
    if not ptr_records:
        return ["No PTR records found."]
    return [
        f"  - {rec.get('ip', 'N/A'):<18} -> {rec.get('hostname', 'N/A')}"
        for rec in ptr_records
    ]


def export_txt_ptr(data: Dict[str, str]) -> str:
    """Formats PTR lookups for the text report."""
    return _create_report_section("Reverse DNS (PTR) Lookups", data, _format_ptr_txt)


def _format_zone_txt(data: Dict[str, Any]) -> List[str]:
    report = [f"Overall Status: {data.get('summary', data.get('status', 'No data.'))}"]
    for server, info in data.get("servers", {}).items():
        report.append(f"  - {server}: {info.get('status', 'Unknown')}")
        if info.get("status") == "Successful":
            report.append(f"    Record Count: {info.get('record_count')}")
    return report


def export_txt_zone(data: Dict[str, Any]) -> str:
    """Formats Zone Transfer results for the text report."""
    return _create_report_section("Zone Transfer (AXFR)", data, _format_zone_txt)


def _format_mail_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for key, value in data.items():  # noqa: E501
        report.append(f"\n[{key.upper()}]")  # noqa: W505
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                report.append(f"  - {sub_key:<15}: {sub_value}")
        else:
            report.append(f"  - {value}")
    return report


def export_txt_mail(data: Dict[str, Any]) -> str:
    """Formats Email Security analysis for the text report."""
    return _create_report_section("Email Security", data, _format_mail_txt)


def _format_whois_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for key, value in data.items():
        if not value or key == "error":
            continue

        value_str = str(value[0]) if isinstance(value, list) and value else str(value)

        if "date" in key and isinstance(value_str, str):
            try:
                dt = datetime.datetime.fromisoformat(value_str.replace(" ", "T"))
                value_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                pass  # Keep original string if parsing fails
        report.append(f"  {key.replace('_', ' ').title():<20}: {value_str}")
    return report


def export_txt_whois(data: Dict[str, Any]) -> str:
    """Formats WHOIS information for the text report."""
    return _create_report_section("WHOIS Information", data, _format_whois_txt)


def _format_nsinfo_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for ns, info in data.items():
        if ns == "dnssec":
            continue
        if isinstance(info, dict):
            ip_str = ", ".join(info.get("ips", [])) or "N/A"
            report.append(
                f"  - {ns}\n    IP(s): {ip_str}\n    ASN: {info.get('asn_description', 'N/A')}"
            )
    report.append(f"\nDNSSEC: {data.get('dnssec', 'Unknown')}")
    return report


def export_txt_nsinfo(data: Dict[str, Any]) -> str:
    """Formats Nameserver Analysis for the text report."""
    return _create_report_section("Nameserver Analysis", data, _format_nsinfo_txt)


def _format_propagation_txt(data: Dict[str, str]) -> List[str]:
    lines = []
    for server, result in data.items():  # type: ignore
        ips = ", ".join(result.get("ips", [result.get("error", "N/A")]))
        lines.append(f"  - {server:<20}: {ips}")
    return lines


def export_txt_propagation(data: Dict[str, str]) -> str:
    """Formats DNS Propagation check for the text report."""
    return _create_report_section(
        "DNS Propagation Check", data, _format_propagation_txt
    )


def _format_security_audit_txt(data: Dict[str, Any]) -> List[str]:
    """Formats the detailed findings from the security audit module."""
    findings = data.get("findings", [])
    if not findings:
        return ["All security checks passed."]

    report = []
    severity_order = ["Critical", "High", "Medium", "Low"]

    for severity in severity_order:
        # Filter findings for the current severity level
        grouped_findings = [f for f in findings if f.get("severity") == severity]
        if not grouped_findings:
            continue

        report.append(f"\n[{severity} Severity Findings]")
        for finding in grouped_findings:
            report.append(f"  - Finding: {finding.get('finding', 'N/A')}")
            report.append(f"    Recommendation: {finding.get('recommendation', 'N/A')}")

    return report


def export_txt_security(data: Dict[str, Any]) -> str:
    """Formats Security Audit for the text report."""
    return _create_report_section("Security Audit", data, _format_security_audit_txt)


def _format_tech_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    if technologies := data.get("technologies"):
        report.append(f"  {'Technologies:':<20}: {', '.join(technologies)}")
    if server := data.get("server"):
        report.append(f"  {'Server:':<20}: {server}")
    return report or ["No technology information found."]


def export_txt_tech(data: Dict[str, Any]) -> str:
    """Formats Technology Detection for the text report."""
    return _create_report_section("Technology Detection", data, _format_tech_txt)


def _format_osint_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    if subdomains := data.get("subdomains", []):
        report.append("\nSubdomains:")
        for item in subdomains:
            report.append(f"  - {item}")
    if passive_dns := data.get("passive_dns", []):
        report.append("\nPassive DNS:")
        for item in passive_dns:
            report.append(
                f"  - {item.get('hostname')} -> {item.get('ip')} "
                f"(Last: {item.get('last_seen')})"
            )
    return report or ["No OSINT data found."]


def export_txt_osint(data: Dict[str, Any]) -> str:
    """Formats OSINT Enrichment for the text report."""
    return _create_report_section("OSINT Enrichment", data, _format_osint_txt)


def _format_ssl_txt(data: Dict[str, Any]) -> List[str]:
    report = [
        f"Subject: {data.get('subject', 'N/A')}",
        f"Issuer: {data.get('issuer', 'N/A')}",
    ]
    if valid_from := data.get("valid_from"):
        report.append(
            "Valid From: "
            f"{datetime.datetime.fromtimestamp(valid_from).strftime('%Y-%m-%d %H:%M:%S')}"
        )
    if valid_until := data.get("valid_until"):
        report.append(
            "Valid Until: "
            f"{datetime.datetime.fromtimestamp(valid_until).strftime('%Y-%m-%d %H:%M:%S')}"
        )
    if sans := data.get("sans"):  # noqa: W504
        report.extend(["\nSubject Alternative Names:"] + [f"  - {s}" for s in sans])
    return report or ["No SSL/TLS data found."]


def export_txt_ssl(data: Dict[str, Any]) -> str:
    """Formats SSL/TLS Certificate analysis for the text report."""
    return _create_report_section("SSL/TLS Certificate Analysis", data, _format_ssl_txt)


def _format_smtp_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for server, info in data.items():
        if isinstance(info, dict):
            if error := info.get("error"):
                report.append(f"  - {server}: Error - {error}")
                continue
            report.extend(
                [
                    f"  - {server}",
                    f"    Banner: {info.get('banner', 'N/A')}",
                    f"    STARTTLS: {info.get('starttls', 'Unknown')}",
                ]
            )
            if cert_info := info.get("certificate"):
                valid_until_str = "N/A"
                if valid_until := cert_info.get("valid_until"):
                    valid_until_str = datetime.datetime.fromtimestamp(
                        valid_until
                    ).strftime("%Y-%m-%d %H:%M:%S")
                report.extend(
                    [
                        "    Certificate:",
                        f"      Subject: {cert_info.get('subject', 'N/A')}",
                        f"      Valid Until: {valid_until_str}",
                    ]
                )
    return report or ["No SMTP servers were analyzed."]


def export_txt_smtp(data: Dict[str, Any]) -> str:
    """Formats Mail Server (SMTP) analysis for the text report."""
    return _create_report_section("Mail Server (SMTP) Analysis", data, _format_smtp_txt)


def _format_reputation_txt(data: Dict[str, Any]) -> List[str]:
    """Formats IP Reputation analysis for the text report."""
    report = []
    for ip, info in data.items():
        if isinstance(info, dict):
            if error := info.get("error"):
                report.append(f"  - {ip}: Error - {error}")
                continue
            last_reported = info.get("lastReportedAt", "N/A")
            if last_reported and last_reported != "N/A":
                last_reported = datetime.datetime.fromisoformat(
                    last_reported.replace("Z", "+00:00")
                ).strftime("%Y-%m-%d")
            report.append(
                f"  - {ip}: Score: {info.get('abuseConfidenceScore', 0)}, "
                f"Reports: {info.get('totalReports', 0)}, Last Reported: {last_reported}"
            )
    return report or ["No IP reputation data was found."]


def export_txt_reputation(data: Dict[str, Any]) -> str:
    """Formats IP Reputation analysis for the text report."""
    return _create_report_section(
        "IP Reputation Analysis (AbuseIPDB)", data, _format_reputation_txt
    )


def _format_content_hash_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Content Hash analysis for the text report."""
    report = []
    if h := data.get("favicon_murmur32_hash"):
        report.append(f"  {'Favicon Murmur32 Hash:':<25}: {h}")
    if h := data.get("page_sha256_hash"):
        report.append(f"  {'Page Content SHA256:':<25}: {h}")
    return report


def export_txt_content_hash(data: Dict[str, Any]) -> str:
    """Formats Content Hash analysis for the text report."""
    return _create_report_section(
        "Content & Favicon Hashes", data, _format_content_hash_txt
    )


def _format_ct_logs_txt(data: Dict[str, Any]) -> List[str]:
    subdomains = data.get("subdomains", [])
    if subdomains:
        return [f"Found {len(subdomains)} subdomains:"] + [
            f"  - {s}" for s in subdomains
        ]
    return ["No subdomains found in CT logs."]


def export_txt_ct_logs(data: Dict[str, Any]) -> str:
    """Formats CT Log analysis for the text report."""
    return _create_report_section(
        "Certificate Transparency Log Analysis", data, _format_ct_logs_txt
    )


def _format_waf_detection_txt(data: Dict[str, Any]) -> List[str]:
    """Formats WAF Detection for the text report."""
    if detected_wafs := data.get("detected_wafs", []):
        details = data.get("details", {})
        report = [f"Identified: {', '.join(detected_wafs)}"]
        report.extend(
            [f"  - {waf}: {details.get(waf, 'No details.')}" for waf in detected_wafs]
        )
        return report
    return ["No WAF identified from response headers."]


def export_txt_waf_detection(data: Dict[str, Any]) -> str:
    """Formats WAF Detection analysis for the text report."""
    return _create_report_section("WAF Detection", data, _format_waf_detection_txt)


def _format_dane_txt(data: Dict[str, Any]) -> List[str]:
    report = [f"Status for _443._tcp (HTTPS): {data.get('status', 'Not Found')}"]
    if records := data.get("records", []):
        report.extend(["\nRecords:"] + [f"  - {r}" for r in records])
    return report


def export_txt_dane(data: Dict[str, Any]) -> str:
    """Formats DANE/TLSA analysis for the text report."""
    return _create_report_section("DANE/TLSA Record Analysis", data, _format_dane_txt)


def _format_geolocation_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for ip, info in data.items():
        if isinstance(info, dict) and (error := info.get("error")):
            report.append(f"  - {ip}: Error - {error}")

        elif isinstance(info, dict):
            report.append(
                (
                    f"  - {ip}: {info.get('city', 'N/A')}, "
                    f"{info.get('country', 'N/A')} "
                    f"(ISP: {info.get('isp', 'N/A')})"
                )
            )
    return report


def export_txt_geolocation(data: Dict[str, Any]) -> str:
    """Formats IP Geolocation analysis for the text report."""
    return _create_report_section("IP Geolocation", data, _format_geolocation_txt)


def _format_http_headers_txt(data: Dict[str, Any]) -> List[str]:
    """Formats HTTP Headers for the text report."""
    report = [f"Final URL: {data.get('final_url')}\n"]
    for header, info in data.get("analysis", {}).items():
        value_str = f" - Value: {info.get('value', '')}" if info.get("value") else ""
        report.append(f"  - {header}: {info.get('status', 'Unknown')}{value_str}")
    if recommendations := data.get("recommendations", []):
        report.extend(
            ["\nRecommendations:"] + [f"  • {rec}" for rec in recommendations]
        )
    return report


def export_txt_http_headers(data: Dict[str, Any]) -> str:
    """Formats HTTP Security Headers analysis for the text report."""
    return _create_report_section(
        "HTTP Security Headers Analysis", data, _format_http_headers_txt
    )


def _format_port_scan_txt(data: Dict[str, Any]) -> List[str]:
    scan_results = data.get("scan_results", [])
    if not scan_results:
        return ["No open ports found among common ports."]
    return [
        f"  - {res['ip']}: {', '.join(map(str, res.get('ports', [])))}"
        for res in scan_results
    ]


def export_txt_port_scan(data: Dict[str, Any]) -> str:
    """Formats Open Port Scan results for the text report."""
    return _create_report_section("Open Port Scan", data, _format_port_scan_txt)


def _format_subdomain_takeover_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Subdomain Takeover results for the text report."""
    if not (vulnerable := data.get("vulnerable", [])):
        return ["No potential subdomain takeovers found."]
    report = [f"Found {len(vulnerable)} potential subdomain takeovers:"]
    for item in vulnerable:
        report.extend(
            [
                f"\n  - Subdomain: {item['subdomain']}",
                f"    Service: {item['service']}",
                f"    CNAME Target: {item['cname_target']}",
            ]
        )
    return report


def export_txt_subdomain_takeover(data: Dict[str, Any]) -> str:
    """Formats Subdomain Takeover results for the text report."""
    return _create_report_section(
        "Subdomain Takeover", data, _format_subdomain_takeover_txt
    )


def _format_cloud_enum_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Cloud Enumeration for the text report."""
    report = []
    s3 = data.get("s3_buckets", [])
    azure_blobs = data.get("azure_blobs", [])
    if not s3 and not azure_blobs:
        return ["No public S3 or Azure Blob containers found."]
    if s3:
        report.append("Discovered S3 Buckets:")
        for bucket in s3:
            report.append(f"  - {bucket.get('url')} (Status: {bucket.get('status')})")
    if azure_blobs:
        if s3:
            report.append("")
        report.append("Discovered Azure Blob Containers:")
        for blob in azure_blobs:
            report.append(f"  - {blob.get('url')} (Status: {blob.get('status')})")
    return report


def export_txt_cloud_enum(data: Dict[str, Any]) -> str:
    """Formats Cloud Service Enumeration results for the text report."""
    return _create_report_section(
        "Cloud Service Enumeration", data, _format_cloud_enum_txt
    )


def _format_dnsbl_check_txt(data: Dict[str, Any]) -> List[str]:
    if not (listed_ips := data.get("listed_ips", [])):
        return ["No IP addresses found on common DNS blocklists."]
    report = [f"Found {len(listed_ips)} IP(s) on DNS blocklists:"]
    for item in listed_ips:
        report.extend(
            [
                f"\n  - IP Address: {item['ip']}",
                f"    Listed on: {', '.join(item.get('listed_on', []))}",
            ]
        )
    return report


def export_txt_dnsbl_check(data: Dict[str, Any]) -> str:
    """Formats DNS Blocklist (DNSBL) check results for the text report."""
    return _create_report_section(
        "DNS Blocklist (DNSBL) Check", data, _format_dnsbl_check_txt
    )


def _format_open_redirect_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Open Redirect scan results for the text report."""
    vulnerable_urls = data.get("vulnerable_urls", [])
    if not vulnerable_urls:
        return ["No potential open redirects found."]

    report = [f"Found {len(vulnerable_urls)} potential open redirects:"]
    for item in vulnerable_urls:
        report.extend(
            [
                f"\n  - Vulnerable URL: {item['url']}",
                f"    Redirects To:   {item['redirects_to']}",
            ]
        )
    return report


def export_txt_open_redirect(data: Dict[str, Any]) -> str:
    """Formats Open Redirect scan results for the text report."""
    return _create_report_section("Open Redirect Scan", data, _format_open_redirect_txt)


def _format_security_txt_txt(data: Dict[str, Any]) -> List[str]:
    """Formats security.txt results for the text report."""
    if not data.get("found"):
        return ["No security.txt file found at standard locations."]

    report = [f"Found at: {data.get('url', 'N/A')}\n"]
    parsed_content = data.get("parsed", {})
    if not parsed_content:
        return report + ["File was empty or could not be parsed."]

    for key, value in parsed_content.items():
        if isinstance(value, list):
            for v in value:
                report.append(f"  {key:<20}: {v}")
        else:
            report.append(f"  {key:<20}: {value}")
    return report


def export_txt_security_txt(data: Dict[str, Any]) -> str:
    """Formats security.txt analysis for the text report."""
    return _create_report_section("Security.txt Check", data, _format_security_txt_txt)


def _format_robots_txt_txt(data: Dict[str, Any]) -> List[str]:
    """Formats robots.txt results for the text report."""
    if not data.get("found"):
        return ["No robots.txt file found."]

    report = [f"Found at: {data.get('url', 'N/A')}\n"]
    if disallowed := data.get("disallowed_sensitive"):
        report.extend(
            ["Found potentially sensitive disallowed paths:"]
            + [f"  - {path}" for path in disallowed]
        )
    return report


def export_txt_robots_txt(data: Dict[str, Any]) -> str:
    """Formats robots.txt analysis for the text report."""
    return _create_report_section("Robots.txt Check", data, _format_robots_txt_txt)
