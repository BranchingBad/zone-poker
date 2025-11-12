#!/usr/bin/env python3
from typing import Dict, List, Any
from datetime import datetime

# List of substrings indicating weak cipher suites.
# Based on recommendations from security standards.
WEAK_CIPHER_SUBSTRINGS = [
    "_RC4_",
    "_DES_",
    "_3DES_",
    "_NULL_",
    "_MD5",
    "ADH-",  # Anonymous Diffie-Hellman
    "AECDH-",# Anonymous Elliptic Curve Diffie-Hellman
    "-EXP-", # Export-grade
]

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
    **kwargs
) -> Dict[str, Dict[str, str]]:
    """Runs a comprehensive audit for DNS and web security misconfigurations."""
    audit: Dict[str, Dict[str, str]] = {}
    
    # SPF Policy
    spf_data = mail_info.get("spf", {})
    if "warning" in spf_data:
        audit["SPF Record"] = {"status": "Weak", "details": spf_data["warning"]}
    elif spf_data.get("all_policy") == "?all":
        audit["SPF Policy"] = {"status": "Weak", "details": "Policy is '?all' (Neutral), which does not prevent spoofing."}
    elif spf_data.get("all_policy") == "~all":
        audit["SPF Policy"] = {"status": "Moderate", "details": "Policy is '~all' (SoftFail), which is not fully secure."}
    elif spf_data.get("all_policy") == "-all":
        audit["SPF Policy"] = {"status": "Secure", "details": "Policy is '-all' (HardFail), which is the recommended setting."}
    else:
        audit["SPF Policy"] = {"status": "Weak", "details": "No SPF record or 'all' mechanism found."}

    # DMARC Policy
    dmarc_data = mail_info.get("dmarc", {})
    if dmarc_data.get("p") == "none":
        details = "Policy 'p=none' is in monitoring mode and does not prevent spoofing."
        if not dmarc_data.get("rua"):
            details += " Additionally, no 'rua' reporting address is configured."
        audit["DMARC Policy"] = {"status": "Weak", "details": details}
    elif dmarc_data.get("p") in ("quarantine", "reject"):
        audit["DMARC Policy"] = {"status": "Secure", "details": f"Policy is '{dmarc_data['p']}', which protects against spoofing."}
    else:
        audit["DMARC Policy"] = {"status": "Weak", "details": "No DMARC record found or policy is misconfigured."}

    # CAA Record
    if records_info.get("CAA"):
        audit["CAA Record"] = {"status": "Secure", "details": "Present, restricting which CAs can issue certificates."}
    else:
        audit["CAA Record"] = {"status": "Weak", "details": "Not found, allowing any Certificate Authority to issue certificates."}

    # DNSSEC
    dnssec_status = nsinfo_info.get("dnssec", "Not Enabled")
    if dnssec_status.startswith("Enabled"):
        dnssec_final_status = "Secure"
    elif dnssec_status.startswith("Partial"):
        dnssec_final_status = "Moderate"
    else: # "Not Enabled" or other cases
        dnssec_final_status = "Weak"
    audit["DNSSEC"] = {"status": dnssec_final_status, "details": dnssec_status}

    # Zone Transfer
    axfr_summary = zone_info.get("summary", "Not Checked")
    audit["Zone Transfer"] = {"status": "Vulnerable" if "Vulnerable" in axfr_summary else "Secure", "details": axfr_summary}

    # --- Web Security Audits ---

    # HTTP Security Headers
    missing_headers = [
        header for header, result in headers_info.get("analysis", {}).items()
        if result.get("status") == "Missing"
    ]
    if missing_headers:
        audit["HTTP Headers"] = {"status": "Weak", "details": f"Missing critical headers: {', '.join(missing_headers)}."}
    else:
        audit["HTTP Headers"] = {"status": "Secure", "details": "All key security headers are present."}

    # HSTS Policy Strength
    hsts_analysis = headers_info.get("analysis", {}).get("Strict-Transport-Security", {})
    if hsts_analysis.get("status") == "Weak":
        audit["HSTS Policy"] = {"status": "Moderate", "details": "HSTS is present but with a weak 'max-age' (< 1 year)."}
    elif hsts_analysis.get("status") == "Strong":
        audit["HSTS Policy"] = {"status": "Secure", "details": "HSTS is enabled with a strong policy."}

    # SSL/TLS Certificate Validity
    if "error" in ssl_info:
        audit["SSL/TLS Certificate"] = {"status": "Weak", "details": f"Could not be analyzed: {ssl_info['error']}"}
    elif valid_until := ssl_info.get("valid_until"):
        if datetime.now().timestamp() > valid_until:
            audit["SSL/TLS Certificate"] = {"status": "Weak", "details": "Certificate is expired."}
        else:
            audit["SSL/TLS Certificate"] = {"status": "Secure", "details": "Certificate is valid."}

    # SSL/TLS Cipher Suites
    if cipher_info := ssl_info.get("cipher"):
        # cipher_info is a tuple: ('name', 'version', bits)
        cipher_name = cipher_info[0]
        if any(weak_str in cipher_name for weak_str in WEAK_CIPHER_SUBSTRINGS):
            audit["SSL/TLS Ciphers"] = {"status": "Weak", "details": f"Connection uses a weak cipher suite: {cipher_name}."}


    # Subdomain Takeover
    if vulnerable_takeovers := takeover_info.get("vulnerable", []):
        audit["Subdomain Takeover"] = {"status": "Vulnerable", "details": f"Found {len(vulnerable_takeovers)} potentially vulnerable subdomains."}

    # DNSBL Listing
    if listed_ips := dnsbl_info.get("listed_ips", []):
        audit["IP Blocklist Status"] = {"status": "Weak", "details": f"Found {len(listed_ips)} IP(s) on DNS blocklists."}

    # Open Ports Check
    open_ports_summary = []
    for ip, ports in port_scan_info.items():
        if ports:
            open_ports_summary.append(f"{ip}: {', '.join(map(str, ports))}")
    if open_ports_summary:
        audit["Open Ports"] = {"status": "Weak", "details": f"Found open ports, which could increase attack surface. Details: {'; '.join(open_ports_summary)}"}

    return audit