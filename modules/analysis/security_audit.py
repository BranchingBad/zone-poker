#!/usr/bin/env python3
"""
Zone-Poker - Security Audit Module
"""

import datetime
from typing import Any, Dict, List

from .http_headers import HEADER_CHECKS

AUDIT_CHECKS = [
    # --- Mail Security ---
    {
        "data_key": "mail_info",
        "condition": lambda d: not d.get("spf") or "status" in d.get("spf", {}),
        "finding": "Missing SPF Record",
        "severity": "High",
        "recommendation": "Implement an SPF record to prevent email spoofing.",
    },
    {
        "data_key": "mail_info",
        "condition": lambda d: d.get("spf", {}).get("all_policy") == "?all",
        "finding": "Permissive SPF Policy (?all)",
        "severity": "Medium",
        "recommendation": "Strengthen the SPF policy to `~all` (SoftFail) or `-all` (HardFail).",
    },
    {
        "data_key": "mail_info",
        "condition": lambda d: d.get("spf", {}).get("all_policy") == "+all",
        "finding": "Overly Permissive SPF Policy (+all)",
        "severity": "Critical",
        "recommendation": ("Immediately change `+all` to `~all` or `-all`. `+all` allows " "anyone to send email on your behalf."),
    },
    {
        "data_key": "mail_info",
        "condition": lambda d: not d.get("dmarc") or "status" in d.get("dmarc", {}),
        "finding": "Missing DMARC Record",
        "severity": "High",
        "recommendation": "Implement a DMARC record to control SPF/DKIM failures and receive reports.",
    },
    {
        "data_key": "mail_info",
        "condition": lambda d: d.get("dmarc", {}).get("p") == "none",
        "finding": "Weak DMARC Policy (p=none)",
        "severity": "Medium",
        "recommendation": "Transition to `p=quarantine` or `p=reject` after monitoring reports for legitimate mail sources.",
    },
    # --- DNS Security ---
    {
        "data_key": "records_info",
        "condition": lambda d: not d.get("CAA"),
        "finding": "Missing CAA Record",
        "severity": "Low",
        "recommendation": "Implement CAA records to restrict which Certificate Authorities can issue certificates for your domain.",
    },
    {
        "data_key": "zone_info",
        "condition": lambda d: d.get("summary") == "Vulnerable (Zone Transfer Successful)",
        "finding": "Zone Transfer (AXFR) Enabled",
        "severity": "High",
        "recommendation": "Disable zone transfers to untrusted IP addresses on your authoritative nameservers.",
    },
    {
        "data_key": "nsinfo_info",
        "condition": lambda d: "Not Enabled" in d.get("dnssec", ""),
        "finding": "DNSSEC Not Enabled",
        "severity": "Medium",
        "recommendation": "Enable DNSSEC to protect against DNS spoofing and cache poisoning attacks.",
    },
    {
        "data_key": "records_info",
        "condition": lambda d: not d.get("NSEC") and not d.get("NSEC3"),
        "finding": "Zone Walking Possible",
        "severity": "Low",
        "recommendation": "Implement NSEC3 to prevent zone walking, which can enumerate all records in a zone.",
    },
    # --- Web Security ---
    {
        "data_key": "redirect_info",
        "condition": lambda d: d.get("vulnerable_urls"),
        "finding": "Open Redirect",
        "severity": "Medium",
        "recommendation": lambda d: (
            f"Found {len(d['vulnerable_urls'])} potential open redirect(s). " "Validate and sanitize all user-supplied URLs in redirects."
        ),
    },
    {
        "data_key": "ssl_info",
        "condition": lambda d: d.get("valid_until") and datetime.datetime.now().timestamp() > d["valid_until"],
        "finding": "Expired SSL/TLS Certificate",
        "severity": "High",
        "recommendation": "Renew the SSL/TLS certificate immediately to restore trust and encrypted communication.",
    },
    {
        "data_key": "ssl_info",
        "condition": lambda d: d.get("cipher")
        and isinstance(d["cipher"], (list, tuple))
        and d["cipher"]
        and any(keyword in d["cipher"][0] for keyword in ["RC4", "3DES", "DES", "MD5", "NULL", "EXPORT"]),
        "finding": "Weak SSL/TLS Cipher Suite",
        "severity": "Medium",
        "recommendation": (
            "The server supports weak cipher suites. Reconfigure the server to use "
            "modern ciphers (e.g., AES-GCM, ChaCha20-Poly1305) and disable legacy ones."
        ),
    },
    {
        "data_key": "takeover_info",
        "condition": lambda d: d.get("vulnerable"),
        "finding": "Subdomain Takeover",
        "severity": "Critical",
        "recommendation": lambda d: (
            f"Found {len(d['vulnerable'])} potential subdomain takeover(s). "
            "Remove the dangling DNS records or claim the external resources."
        ),
    },
    # --- Reputation & Infrastructure ---
    {
        "data_key": "reputation_info",
        "condition": lambda d: any(isinstance(info, dict) and info.get("abuseConfidenceScore", 0) > 75 for info in d.values()),
        "finding": "High-Risk IP Reputation",
        "severity": "High",
        "recommendation": lambda d: (
            f"{len([i for i in d.values() if isinstance(i, dict) and i.get('abuseConfidenceScore', 0) > 75])} "
            "IP(s) have a high abuse score. Investigate for malicious activity."
        ),
    },
]


def security_audit(all_data: Dict[str, Any], **kwargs: Any) -> Dict[str, List[Dict[str, str]]]:
    """
    Runs a basic audit for DNS and web security misconfigurations.
    """
    findings: List[Dict[str, str]] = []

    for check in AUDIT_CHECKS:
        data = all_data.get(check["data_key"], {})
        if isinstance(data, dict) and "error" not in data and check["condition"](data):
            recommendation = check["recommendation"]
            findings.append(
                {
                    "finding": check["finding"],
                    "severity": check["severity"],
                    "recommendation": (recommendation(data) if callable(recommendation) else recommendation),
                }
            )

    # Handle header checks separately as they can return multiple findings
    headers_info = all_data.get("headers_info", {})
    if isinstance(headers_info, dict) and "error" not in headers_info:
        analysis = headers_info.get("analysis", {})
        for header_name, check_config in HEADER_CHECKS.items():
            details = analysis.get(header_name, {})
            if details.get("status") in ("Missing", "Weak", "Invalid", "Disabled"):
                findings.append(
                    {
                        "finding": f"Insecure Header: {header_name}",
                        "severity": check_config.get("severity", "Low"),
                        "recommendation": details.get("recommendation") or check_config.get("recommendation"),
                    }
                )

    # --- ROBOTS.TXT CHECK ---
    # This check is separate as it doesn't fit the AUDIT_CHECKS lambda model
    robots_data = all_data.get("robots_info", {})
    if isinstance(robots_data, dict) and "error" not in robots_data:
        sensitive_paths = robots_data.get("disallowed_sensitive", [])

        if sensitive_paths:
            findings.append(
                {
                    "finding": "Sensitive Paths in robots.txt",
                    "severity": "Low",
                    "recommendation": (
                        f"robots.txt disallows crawling of {len(sensitive_paths)} potentially sensitive path(s): "
                        f"{', '.join(sensitive_paths)}. Review these paths to ensure they do not "
                        "expose sensitive information or endpoints."
                    ),
                }
            )

    # Sort findings by severity (Critical, High, Medium, Low)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", ""), 4))

    return {"findings": findings}
