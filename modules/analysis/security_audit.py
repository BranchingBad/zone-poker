#!/usr/bin/env python3
"""
Zone-Poker - Security Audit Module
"""
from typing import Dict, Any, List

AUDIT_CHECKS = [
    # --- Mail Security ---
    {
        "data_key": "mail_info",
        "condition": lambda d: not d.get("spf") or "status" in d.get("spf", {}),
        "finding": "Missing SPF Record", "severity": "High",
        "recommendation": "Implement an SPF record to prevent email spoofing."
    },
    {
        "data_key": "mail_info",
        "condition": lambda d: d.get("spf", {}).get("all_policy") == "?all",
        "finding": "Permissive SPF Policy (?all)", "severity": "Medium",
        "recommendation": "Strengthen the SPF policy to `~all` (SoftFail) or `-all` (HardFail)."
    },
    {
        "data_key": "mail_info",
        "condition": lambda d: d.get("spf", {}).get("all_policy") == "+all",
        "finding": "Overly Permissive SPF Policy (+all)", "severity": "Critical",
        "recommendation": "Immediately change `+all` to `~all` or `-all`. `+all` allows anyone to send email on your behalf."
    },
    {
        "data_key": "mail_info",
        "condition": lambda d: not d.get("dmarc") or "status" in d.get("dmarc", {}),
        "finding": "Missing DMARC Record", "severity": "High",
        "recommendation": "Implement a DMARC record to control SPF/DKIM failures and receive reports."
    },
    {
        "data_key": "mail_info",
        "condition": lambda d: d.get("dmarc", {}).get("p") == "none",
        "finding": "Weak DMARC Policy (p=none)", "severity": "Medium",
        "recommendation": "Transition to `p=quarantine` or `p=reject` after monitoring reports for legitimate mail sources."
    },
    # --- DNS Security ---
    {
        "data_key": "records_info",
        "condition": lambda d: not d.get("CAA"),
        "finding": "Missing CAA Record", "severity": "Low",
        "recommendation": "Implement CAA records to restrict which Certificate Authorities can issue certificates for your domain."
    },
    {
        "data_key": "zone_info",
        "condition": lambda d: d.get("summary") == "Vulnerable (Zone Transfer Successful)",
        "finding": "Zone Transfer (AXFR) Enabled", "severity": "High",
        "recommendation": "Disable zone transfers to untrusted IP addresses on your authoritative nameservers."
    },
    {
        "data_key": "nsinfo_info",
        "condition": lambda d: "Not Enabled" in d.get("dnssec", ""),
        "finding": "DNSSEC Not Enabled", "severity": "Medium",
        "recommendation": "Enable DNSSEC to protect against DNS spoofing and cache poisoning attacks."
    },
    # --- Web Security ---
    {
        "data_key": "redirect_info",
        "condition": lambda d: d.get("vulnerable_urls"),
        "finding": "Open Redirect", "severity": "Medium",
        "recommendation": lambda d: f"Found {len(d['vulnerable_urls'])} potential open redirect(s). Validate and sanitize all user-supplied URLs in redirects."
    },
]

def security_audit(
    records_info: Dict[str, Any],
    mail_info: Dict[str, Any],
    nsinfo_info: Dict[str, Any],
    zone_info: Dict[str, Any],
    headers_info: Dict[str, Any],
    **kwargs: Any
) -> Dict[str, List[Dict[str, str]]]:
    """
    Runs a basic audit for DNS and web security misconfigurations.
    """
    findings: List[Dict[str, str]] = []
    all_scan_data = {
        "records_info": records_info,
        "mail_info": mail_info,
        "nsinfo_info": nsinfo_info,
        "zone_info": zone_info,
        "headers_info": headers_info,
        **kwargs
    }

    for check in AUDIT_CHECKS:
        data = all_scan_data.get(check["data_key"], {})
        if isinstance(data, dict) and "error" not in data and check["condition"](data):
            recommendation = check["recommendation"]
            findings.append({
                "finding": check["finding"],
                "severity": check["severity"],
                "recommendation": recommendation(data) if callable(recommendation) else recommendation,
            })

    # Handle header checks separately as they can return multiple findings
    if isinstance(headers_info, dict) and "error" not in headers_info:
        for header, details in headers_info.get("analysis", {}).items():
            if details.get("status") in ("Missing", "Weak", "Invalid"):
                findings.append({
                    "finding": f"Insecure Header: {header}",
                    "severity": "High",  # Simplified for now
                    "recommendation": details.get("recommendation", headers_info.get("recommendations", [])[0] if headers_info.get("recommendations") else "Strengthen header configuration.")
                })

    # Sort findings by severity (Critical, High, Medium, Low)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", ""), 4))

    return {"findings": findings}