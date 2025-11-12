#!/usr/bin/env python3
from typing import Dict, List, Any
from datetime import datetime
import logging

# List of substrings indicating weak cipher suites.
# Based on recommendations from security standards.
WEAK_CIPHER_SUBSTRINGS = [
    "_RC4_",
    "_DES_",
    "_3DES_",
    "_NULL_",
    "_MD5",
    "ADH-",  # Anonymous Diffie-Hellman
    "AECDH-",  # Anonymous Elliptic Curve Diffie-Hellman
    "-EXP-",  # Export-grade
]

logger = logging.getLogger(__name__)


def _add_audit_entry(audit: Dict, check_name: str, status: str, details: str):
    """Helper to create a consistent audit entry."""
    audit[check_name] = {"status": status, "details": details}


def security_audit(
    records_info: Dict[str, List[Dict[str, Any]]],
    mail_info: Dict[str, Any],
    nsinfo_info: Dict[str, Any],
    zone_info: Dict[str, Any],
    headers_info: Dict[str, Any],
    ssl_info: Dict[str, Any],
    takeover_info: Dict[str, Any],
    dnsbl_info: Dict[str, Any],
    port_scan_info: Dict[str, Any],
    reputation_info: Dict[str, Any],  # Added for IP reputation check
    **kwargs,
) -> Dict[str, Dict[str, str]]:
    """Runs a comprehensive audit for DNS and web security misconfigurations."""
    audit: Dict[str, Dict[str, str]] = {}
    _audit_dns_records(audit, records_info, mail_info, nsinfo_info, zone_info)
    _audit_web_security(audit, headers_info, ssl_info, takeover_info)
    _audit_reputation_and_network(audit, dnsbl_info, port_scan_info, reputation_info)
    return audit


def _audit_dns_records(
    audit: Dict, records_info: Dict, mail_info: Dict, nsinfo_info: Dict, zone_info: Dict
):
    """Audits DNS-related security configurations (SPF, DMARC, DNSSEC, etc.)."""
    # --- SPF Policy ---
    spf_data = mail_info.get("spf", {})
    if "warning" in spf_data:
        _add_audit_entry(audit, "SPF Record", "Weak", spf_data["warning"])
    elif spf_data.get("all_policy") == "?all":
        _add_audit_entry(
            audit,
            "SPF Policy",
            "Weak",
            "Policy is '?all' (Neutral), which does not prevent spoofing.",
        )
    elif spf_data.get("all_policy") == "~all":
        _add_audit_entry(
            audit,
            "SPF Policy",
            "Moderate",
            "Policy is '~all' (SoftFail), which is not fully secure.",
        )
    elif spf_data.get("all_policy") == "-all":
        _add_audit_entry(
            audit,
            "SPF Policy",
            "Secure",
            "Policy is '-all' (HardFail), which is the recommended setting.",
        )
    else:
        _add_audit_entry(
            audit, "SPF Policy", "Weak", "No SPF record or 'all' mechanism found."
        )

    # --- DMARC Policy ---
    dmarc_data = mail_info.get("dmarc", {})
    if dmarc_data.get("p") == "none":
        details = "Policy 'p=none' is in monitoring mode and does not prevent spoofing."
        if not dmarc_data.get("rua"):
            details += " Additionally, no 'rua' reporting address is configured."
        _add_audit_entry(audit, "DMARC Policy", "Weak", details)
    elif dmarc_data.get("p") in ("quarantine", "reject"):
        _add_audit_entry(
            audit,
            "DMARC Policy",
            "Secure",
            f"Policy is '{dmarc_data['p']}', which protects against spoofing.",
        )
    else:
        _add_audit_entry(
            audit,
            "DMARC Policy",
            "Weak",
            "No DMARC record found or policy is misconfigured.",
        )

    # --- CAA Record ---
    if records_info.get("CAA"):
        _add_audit_entry(
            audit,
            "CAA Record",
            "Secure",
            "Present, restricting which CAs can issue certificates.",
        )
    else:
        _add_audit_entry(
            audit,
            "CAA Record",
            "Weak",
            "Not found, allowing any Certificate Authority to issue certificates.",
        )

    # --- DNSSEC ---
    dnssec_status = nsinfo_info.get("dnssec", "Not Enabled")
    if dnssec_status.startswith("Enabled"):
        status = "Secure"
    elif dnssec_status.startswith("Partial"):
        status = "Moderate"
    else:
        status = "Weak"
    _add_audit_entry(audit, "DNSSEC", status, dnssec_status)

    # --- DNSSEC NSEC/NSEC3 Check ---
    if "NSEC" in records_info:
        _add_audit_entry(
            audit,
            "DNSSEC Zone Walking",
            "Weak",
            "Uses NSEC, which allows for zone walking to enumerate all records.",
        )
    elif "NSEC3" in records_info:
        _add_audit_entry(
            audit,
            "DNSSEC Zone Walking",
            "Secure",
            "Uses NSEC3, which prevents zone walking.",
        )

    # --- Zone Transfer ---
    axfr_summary = zone_info.get("summary", "Not Checked")
    status = "Vulnerable" if "Vulnerable" in axfr_summary else "Secure"
    _add_audit_entry(audit, "Zone Transfer", status, axfr_summary)


def _audit_web_security(
    audit: Dict, headers_info: Dict, ssl_info: Dict, takeover_info: Dict
):
    """Audits web-related security configurations (headers, SSL, etc.)."""
    # --- HTTP Security Headers ---
    missing_headers = [
        header
        for header, result in headers_info.get("analysis", {}).items()
        if result.get("status") == "Missing"
    ]
    if missing_headers:
        _add_audit_entry(
            audit,
            "HTTP Headers",
            "Weak",
            f"Missing critical headers: {', '.join(missing_headers)}.",
        )
    else:
        _add_audit_entry(
            audit, "HTTP Headers", "Secure", "All key security headers are present."
        )

    # --- HSTS Policy Strength ---
    hsts_analysis = headers_info.get("analysis", {}).get(
        "Strict-Transport-Security", {}
    )
    if hsts_analysis.get("status") == "Weak":
        _add_audit_entry(
            audit,
            "HSTS Policy",
            "Moderate",
            "HSTS is present but with a weak 'max-age' (< 1 year).",
        )
    elif hsts_analysis.get("status") == "Strong":
        _add_audit_entry(
            audit, "HSTS Policy", "Secure", "HSTS is enabled with a strong policy."
        )

    # --- Content-Security-Policy ---
    csp_analysis = headers_info.get("analysis", {}).get("Content-Security-Policy", {})
    if csp_analysis.get("status") == "Missing":
        _add_audit_entry(
            audit,
            "CSP",
            "Weak",
            "Content-Security-Policy header is missing, increasing XSS risk.",
        )
    else:
        _add_audit_entry(
            audit, "CSP", "Secure", "Content-Security-Policy header is present."
        )

    # --- SSL/TLS Certificate Validity ---
    if "error" in ssl_info:
        _add_audit_entry(
            audit,
            "SSL/TLS Certificate",
            "Weak",
            f"Could not be analyzed: {ssl_info['error']}",
        )
    elif valid_until := ssl_info.get("valid_until"):
        if datetime.now().timestamp() > valid_until:
            _add_audit_entry(
                audit, "SSL/TLS Certificate", "Weak", "Certificate is expired."
            )
        else:
            _add_audit_entry(
                audit, "SSL/TLS Certificate", "Secure", "Certificate is valid."
            )

    # --- SSL/TLS Cipher Suites ---
    if cipher_info := ssl_info.get("cipher"):
        cipher_name = cipher_info[0]
        if any(weak_str in cipher_name for weak_str in WEAK_CIPHER_SUBSTRINGS):
            _add_audit_entry(
                audit,
                "SSL/TLS Ciphers",
                "Weak",
                f"Connection uses a weak cipher suite: {cipher_name}.",
            )

    # --- Subdomain Takeover ---
    if vulnerable_takeovers := takeover_info.get("vulnerable", []):
        _add_audit_entry(
            audit,
            "Subdomain Takeover",
            "Vulnerable",
            f"Found {len(vulnerable_takeovers)} potentially vulnerable subdomains.",
        )


def _audit_reputation_and_network(
    audit: Dict, dnsbl_info: Dict, port_scan_info: Dict, reputation_info: Dict
):
    """Audits IP reputation and open network ports."""
    # --- DNSBL Listing ---
    if listed_ips := dnsbl_info.get("listed_ips", []):
        _add_audit_entry(
            audit,
            "IP Blocklist Status",
            "Weak",
            f"Found {len(listed_ips)} IP(s) on DNS blocklists.",
        )

    # --- IP Reputation (AbuseIPDB) ---
    high_risk_ips = [
        ip
        for ip, info in reputation_info.items()
        if isinstance(info, dict) and info.get("abuseConfidenceScore", 0) > 75
    ]
    if high_risk_ips:
        _add_audit_entry(
            audit,
            "IP Reputation",
            "Weak",
            f"Found {len(high_risk_ips)} IP(s) with high abuse scores: {', '.join(high_risk_ips)}.",
        )

    # --- Open Ports Check ---
    open_ports_summary = []
    for ip, ports in port_scan_info.items():
        if ports:
            open_ports_summary.append(f"{ip}: {', '.join(map(str, ports))}")
    if open_ports_summary:
        _add_audit_entry(
            audit,
            "Open Ports",
            "Weak",
            f"Found open ports, which could increase attack surface. Details: {'; '.join(open_ports_summary)}",
        )
