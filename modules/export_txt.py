#!/usr/bin/env python3
"""
Zone-Poker - TXT Report Export Module
Contains all functions for formatting analysis data into a plain text report.
"""
import datetime
import logging
from typing import Dict, List, Any, Callable

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# --- TXT REPORT EXPORT FUNCTIONS ---
# -----------------------------------------------------------------

def _create_report_section(title: str, data: Dict[str, Any], formatter: Callable[[Dict[str, Any]], List[str]]) -> str:
    """
    A helper to create a formatted text report section with a standard header and error handling.
    """
    report = ["="*15 + f" {title} " + "="*15]
    
    if not isinstance(data, dict):
        report.append(f"  Error: Unexpected data format for {title}. Expected dictionary, got {type(data).__name__}.")
        if data:
            report.append(f"  Raw data: {data}")
        return "\n".join(report)

    if not data:
        report.append("No data found for this section.")
    elif data.get("error"):
        error_msg = data['error']
        report.append(f"  Error: {error_msg}")
        logger.debug(f"Skipping report section '{title}' due to pre-existing error: {error_msg}")
    else:
        try:
            report.extend(formatter(data))
        except Exception as e:
            logger.error(f"An unexpected error occurred in the formatter for the '{title}' report section: {e}", exc_info=True)
            report.append(f"  Error: Could not format data for this section due to an unexpected error: {e}")
    return "\n".join(report)

def _format_critical_findings_txt(data: Dict[str, Any]) -> List[str]:
    """Helper to format critical findings for the text report."""
    critical_findings = []
    if "Vulnerable" in data.get('zone_info', {}).get('summary', ''):
        critical_findings.append("Zone Transfer Successful (AXFR): Domain is vulnerable to full zone enumeration.")
    if vulnerable_takeovers := data.get('takeover_info', {}).get('vulnerable', []):
        critical_findings.append(f"Subdomain Takeover: Found {len(vulnerable_takeovers)} potentially vulnerable subdomains.")
    if ssl_info := data.get('ssl_info', {}):
        if ssl_info.get('valid_until') and datetime.datetime.now().timestamp() > ssl_info['valid_until']:
            critical_findings.append("Expired SSL/TLS Certificate: The main web server's certificate has expired.")
    if reputation_info := data.get('reputation_info', {}):
        if high_risk_ips := [ip for ip, info in reputation_info.items() if isinstance(info, dict) and info.get('abuseConfidenceScore', 0) > 75]:
            critical_findings.append(f"High-Risk IP Reputation: {len(high_risk_ips)} IP(s) have a high abuse score ({', '.join(high_risk_ips)}).")
    return [f"  • {finding}" for finding in critical_findings] if critical_findings else ["No critical findings to report."]

def export_txt_critical_findings(data: Dict[str, Any]) -> str:
    return _create_report_section("CRITICAL FINDINGS", data, _format_critical_findings_txt)

def _format_summary_txt(data: Dict[str, Any]) -> List[str]:
    """Helper to format the scan summary for the text report."""
    report = []
    axfr_summary = data.get('zone_info', {}).get('summary', 'Not Found')
    report.append(f"  {'Zone Transfer:':<20}: {axfr_summary}")
    spf_policy = data.get('mail_info', {}).get('spf', {}).get('all_policy', 'Not Found')
    report.append(f"  {'SPF Policy:':<20}: {spf_policy}")
    dmarc_policy = data.get('mail_info', {}).get('dmarc', {}).get('p', 'Not Found')
    report.append(f"  {'DMARC Policy:':<20}: {dmarc_policy}")
    audit_findings = data.get('security_info', {})
    if audit_findings:
        weak_findings = [k for k, v in audit_findings.items() if v.get("status") in ("Weak", "Vulnerable")]
        summary_text = f"Found {len(weak_findings)} issues ({', '.join(weak_findings)})" if weak_findings else "All checks passed"
        report.append(f"  {'Security Audit:':<20}: {summary_text}")
    else:
        report.append(f"  {'Security Audit:':<20}: No data")
    return report

def export_txt_summary(data: Dict[str, Any]) -> str:
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
                if r_type == "MX" and "priority" in record: extra = f" (Priority: {record['priority']})"
                elif r_type == "SRV": extra = f" (P: {record.get('priority')} W: {record.get('weight')} Port: {record.get('port')})"
                elif r_type == "SOA": extra = f" (Serial: {record.get('serial')})"
                report.append(f"  - {value}{extra}")
    return report if report else ["No DNS records found."]

def export_txt_records(data: Dict[str, List[Any]]) -> str:
    return _create_report_section("DNS Records", data, _format_records_txt)

def _format_ptr_txt(data: Dict[str, str]) -> List[str]:
    return [f"  - {ip:<18} -> {hostname}" for ip, hostname in data.items()] or ["No PTR records found."]

def export_txt_ptr(data: Dict[str, str]) -> str:
    return _create_report_section("Reverse DNS (PTR) Lookups", data, _format_ptr_txt)

def _format_zone_txt(data: Dict[str, Any]) -> List[str]:
    report = [f"Overall Status: {data.get('summary', data.get('status', 'No data.'))}"]
    for server, info in data.get('servers', {}).items():
        report.append(f"  - {server}: {info.get('status', 'Unknown')}")
        if info.get('status') == 'Successful': report.append(f"    Record Count: {info.get('record_count')}")
    return report

def export_txt_zone(data: Dict[str, Any]) -> str:
    return _create_report_section("Zone Transfer (AXFR)", data, _format_zone_txt)

def _format_mail_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for key, value in data.items():
        report.append(f"\n[{key.upper()}]")
        if isinstance(value, dict):
            for sub_key, sub_value in value.items(): report.append(f"  - {sub_key:<15}: {sub_value}")
        else: report.append(f"  - {value}")
    return report

def export_txt_mail(data: Dict[str, Any]) -> str:
    return _create_report_section("Email Security", data, _format_mail_txt)

def _format_whois_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for key, value in data.items():
        if value and key != "error":
            value_str = str(value[0]) if isinstance(value, list) else str(value)
            report.append(f"  {key.replace('_', ' ').title():<20}: {value_str}")
    return report

def export_txt_whois(data: Dict[str, Any]) -> str:
    return _create_report_section("WHOIS Information", data, _format_whois_txt)

def _format_nsinfo_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for ns, info in data.items():
        if ns == "dnssec": continue
        if isinstance(info, dict):
            ip_str = ", ".join(info.get('ips', [])) or "N/A"
            report.append(f"  - {ns}\n    IP(s): {ip_str}\n    ASN: {info.get('asn_description', 'N/A')}")
    report.append(f"\nDNSSEC: {data.get('dnssec', 'Unknown')}")
    return report

def export_txt_nsinfo(data: Dict[str, Any]) -> str:
    return _create_report_section("Nameserver Analysis", data, _format_nsinfo_txt)

def _format_propagation_txt(data: Dict[str, str]) -> List[str]:
    return [f"  - {server:<20}: {', '.join(result.get('ips', [result.get('error', 'N/A')]))}" for server, result in data.items()]

def export_txt_propagation(data: Dict[str, str]) -> str:
    return _create_report_section("DNS Propagation Check", data, _format_propagation_txt)

def _format_security_txt(data: Dict[str, str]) -> List[str]:
    report = []
    categories = {
        "DNS Security": ["SPF Policy", "SPF Record", "DMARC Policy", "CAA Record", "DNSSEC", "Zone Transfer"],
        "Web Security": ["HTTP Headers", "HSTS Policy", "SSL/TLS Certificate", "SSL/TLS Ciphers", "Subdomain Takeover"],
        "Reputation": ["IP Blocklist Status"],
        "Network Security": ["Open Ports"],
    }
    displayed_checks = set()
    for category, checks_in_category in categories.items():
        category_checks_present = [c for c in checks_in_category if c in data]
        if not category_checks_present: continue
        report.append(f"\n[{category}]")
        for check in category_checks_present:
            info = data.get(check, {})
            report.append(f"  - {check:<25}: {info.get('status', 'N/A')} ({info.get('details', 'N/A')})")
            displayed_checks.add(check)
    for check, info in data.items():
        if check not in displayed_checks:
            report.append(f"  - {check:<25}: {info.get('status', 'N/A')} ({info.get('details', 'N/A')})")
    return report

def export_txt_security(data: Dict[str, Dict[str, str]]) -> str:
    return _create_report_section("Security Audit", data, _format_security_txt)

def _format_tech_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    if data.get("technologies"): report.append(f"  {'Technologies:':<20}: {', '.join(data['technologies'])}")
    if data.get("server"): report.append(f"  {'Server:':<20}: {data['server']}")
    return report

def export_txt_tech(data: Dict[str, Any]) -> str:
    return _create_report_section("Technology Detection", data, _format_tech_txt)

def _format_osint_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    if subdomains := data.get('subdomains', []):
        report.append("\nSubdomains:")
        for item in subdomains: report.append(f"  - {item}")
    if passive_dns := data.get('passive_dns', []):
        report.append("\nPassive DNS:")
        for item in passive_dns: report.append(f"  - {item.get('hostname')} -> {item.get('ip')} (Last: {item.get('last_seen')})")
    return report

def export_txt_osint(data: Dict[str, Any]) -> str:
    return _create_report_section("OSINT Enrichment", data, _format_osint_txt)

def _format_ssl_txt(data: Dict[str, Any]) -> List[str]:
    report = [f"Subject: {data.get('subject', 'N/A')}", f"Issuer: {data.get('issuer', 'N/A')}"]
    if valid_from := data.get('valid_from'): report.append(f"Valid From: {datetime.datetime.fromtimestamp(valid_from).strftime('%Y-%m-%d %H:%M:%S')}")
    if valid_until := data.get('valid_until'): report.append(f"Valid Until: {datetime.datetime.fromtimestamp(valid_until).strftime('%Y-%m-%d %H:%M:%S')}")
    if sans := data.get('sans'): report.extend(["\nSubject Alternative Names:"] + [f"  - {s}" for s in sans])
    return report

def export_txt_ssl(data: Dict[str, Any]) -> str:
    return _create_report_section("SSL/TLS Certificate Analysis", data, _format_ssl_txt)

def _format_smtp_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for server, info in data.items():
        if isinstance(info, dict):
            if info.get("error"): report.append(f"  - {server}: Error - {info['error']}"); continue
            report.extend([f"  - {server}", f"    Banner: {info.get('banner', 'N/A')}", f"    STARTTLS: {info.get('starttls', 'Unknown')}"])
            if cert_info := info.get('certificate'):
                report.extend(["    Certificate:", f"      Subject: {cert_info.get('subject', 'N/A')}", f"      Valid Until: {datetime.datetime.fromtimestamp(cert_info['valid_until']).strftime('%Y-%m-%d %H:%M:%S') if cert_info.get('valid_until') else 'N/A'}"])
    return report or ["No SMTP servers were analyzed."]

def export_txt_smtp(data: Dict[str, Any]) -> str:
    return _create_report_section("Mail Server (SMTP) Analysis", data, _format_smtp_txt)

def _format_reputation_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for ip, info in data.items():
        if isinstance(info, dict):
            if info.get("error"): report.append(f"  - {ip}: Error - {info['error']}"); continue
            last_reported = info.get('lastReportedAt', 'N/A')
            if last_reported and last_reported != 'N/A': last_reported = datetime.datetime.fromisoformat(last_reported.replace('Z', '+00:00')).strftime('%Y-%m-%d')
            report.append(f"  - {ip}: Score: {info.get('abuseConfidenceScore', 0)}, Reports: {info.get('totalReports', 0)}, Last Reported: {last_reported}")
    return report or ["No IP reputation data was found."]

def export_txt_reputation(data: Dict[str, Any]) -> str:
    return _create_report_section("IP Reputation Analysis (AbuseIPDB)", data, _format_reputation_txt)

def _format_content_hash_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    if h := data.get("favicon_murmur32_hash"): report.append(f"  {'Favicon Murmur32 Hash:':<25}: {h}")
    if h := data.get("page_sha256_hash"): report.append(f"  {'Page Content SHA256:':<25}: {h}")
    return report

def export_txt_content_hash(data: Dict[str, Any]) -> str:
    return _create_report_section("Content & Favicon Hashes", data, _format_content_hash_txt)

def _format_ct_logs_txt(data: Dict[str, Any]) -> List[str]:
    subdomains = data.get('subdomains', [])
    return [f"Found {len(subdomains)} subdomains:"] + [f"  - {s}" for s in subdomains] if subdomains else ["No subdomains found in CT logs."]

def export_txt_ct_logs(data: Dict[str, Any]) -> str:
    return _create_report_section("Certificate Transparency Log Analysis", data, _format_ct_logs_txt)

def _format_waf_detection_txt(data: Dict[str, Any]) -> List[str]:
    if detected_wafs := data.get("detected_wafs", []):
        details = data.get("details", {})
        return [f"Identified: {', '.join(detected_wafs)}"] + [f"  - {waf}: {details.get(waf, 'No details.')}" for waf in detected_wafs]
    return ["No WAF identified from response headers."]

def export_txt_waf_detection(data: Dict[str, Any]) -> str:
    return _create_report_section("WAF Detection", data, _format_waf_detection_txt)

def _format_dane_txt(data: Dict[str, Any]) -> List[str]:
    report = [f"Status for _443._tcp (HTTPS): {data.get('status', 'Not Found')}"]
    if records := data.get("records", []): report.extend(["\nRecords:"] + [f"  - {r}" for r in records])
    return report

def export_txt_dane(data: Dict[str, Any]) -> str:
    return _create_report_section("DANE/TLSA Record Analysis", data, _format_dane_txt)

def _format_geolocation_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    for ip, info in data.items():
        if isinstance(info, dict) and info.get("error"): report.append(f"  - {ip}: Error - {info['error']}")
        elif isinstance(info, dict): report.append(f"  - {ip}: {info.get('city', 'N/A')}, {info.get('country', 'N/A')} (ISP: {info.get('isp', 'N/A')})")
    return report

def export_txt_geolocation(data: Dict[str, Any]) -> str:
    return _create_report_section("IP Geolocation", data, _format_geolocation_txt)

def _format_http_headers_txt(data: Dict[str, Any]) -> List[str]:
    report = [f"Final URL: {data.get('final_url')}\n"]
    for header, info in data.get("analysis", {}).items():
        value_str = f" - Value: {info.get('value', '')}" if info.get('value') else ""
        report.append(f"  - {header}: {info.get('status', 'Unknown')}{value_str}")
    if recommendations := data.get("recommendations", []): report.extend(["\nRecommendations:"] + [f"  • {rec}" for rec in recommendations])
    return report

def export_txt_http_headers(data: Dict[str, Any]) -> str:
    return _create_report_section("HTTP Security Headers Analysis", data, _format_http_headers_txt)

def _format_port_scan_txt(data: Dict[str, Any]) -> List[str]:
    if not data: return ["No open ports found among common ports."]
    return [f"  - {ip}: {', '.join(map(str, ports))}" for ip, ports in data.items()]

def export_txt_port_scan(data: Dict[str, Any]) -> str:
    return _create_report_section("Open Port Scan", data, _format_port_scan_txt)

def _format_subdomain_takeover_txt(data: Dict[str, Any]) -> List[str]:
    if not (vulnerable := data.get("vulnerable", [])): return ["No potential subdomain takeovers found."]
    report = [f"Found {len(vulnerable)} potential subdomain takeovers:"]
    for item in vulnerable: report.extend([f"\n  - Subdomain: {item['subdomain']}", f"    Service: {item['service']}", f"    CNAME Target: {item['cname_target']}"])
    return report

def export_txt_subdomain_takeover(data: Dict[str, Any]) -> str:
    return _create_report_section("Subdomain Takeover", data, _format_subdomain_takeover_txt)

def _format_cloud_enum_txt(data: Dict[str, Any]) -> List[str]:
    report = []
    s3 = data.get("s3_buckets", [])
    azure = data.get("azure_blobs", [])
    if not s3 and not azure: return ["No public S3 or Azure Blob containers found."]
    if s3:
        report.append("Discovered S3 Buckets:")
        for bucket in s3: report.append(f"  - {bucket.get('url')} (Status: {bucket.get('status')})")
    if azure:
        if s3: report.append("")
        report.append("Discovered Azure Blob Containers:")
        for blob in azure: report.append(f"  - {blob.get('url')} (Status: {blob.get('status')})")
    return report

def export_txt_cloud_enum(data: Dict[str, Any]) -> str:
    return _create_report_section("Cloud Service Enumeration", data, _format_cloud_enum_txt)

def _format_dnsbl_check_txt(data: Dict[str, Any]) -> List[str]:
    if not (listed_ips := data.get("listed_ips", [])): return ["No IP addresses found on common DNS blocklists."]
    report = [f"Found {len(listed_ips)} IP(s) on DNS blocklists:"]
    for item in listed_ips: report.extend([f"\n  - IP Address: {item['ip']}", f"    Listed on: {', '.join(item.get('listed_on', []))}"])
    return report

def export_txt_dnsbl_check(data: Dict[str, Any]) -> str:
    return _create_report_section("DNS Blocklist (DNSBL) Check", data, _format_dnsbl_check_txt)