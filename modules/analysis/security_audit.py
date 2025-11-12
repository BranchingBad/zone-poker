#!/usr/bin/env python3
"""
Zone-Poker - Security Audit Module
"""
from typing import Dict, Any, List

def _check_spf_policy(mail_info: Dict[str, Any]) -> Dict[str, str]:
    """Checks the strength of the SPF policy."""
    spf_data = mail_info.get("spf", {})
    all_policy = spf_data.get("all_policy")

    if not spf_data or "status" in spf_data:
        return {
            "finding": "Missing SPF Record",
            "severity": "High",
            "recommendation": "Implement an SPF record to prevent email spoofing."
        }

    if all_policy == "?all":
        return {
            "finding": "Permissive SPF Policy (?all)",
            "severity": "Medium",
            "recommendation": "Strengthen the SPF policy to `~all` (SoftFail) or "
                            "`-all` (HardFail).",
        }
    if all_policy == "+all":
        return {
            "finding": "Overly Permissive SPF Policy (+all)",
            "severity": "Critical",
            "recommendation": "Immediately change `+all` to `~all` or `-all`. "
                            "`+all` allows anyone to send email on your behalf.",
        }
    if not all_policy:
        return {
            "finding": "Incomplete SPF Policy (Missing 'all')",
            "severity": "Medium",
            "recommendation": "Ensure the SPF record ends with a default "
                            "mechanism like `~all` or `-all`.",
        }
    return {}


def _check_dmarc_policy(mail_info: Dict[str, Any]) -> Dict[str, str]:
    """Checks the strength of the DMARC policy."""
    dmarc_data = mail_info.get("dmarc", {})
    policy = dmarc_data.get("p")

    if not dmarc_data or "status" in dmarc_data:
        return {
            "finding": "Missing DMARC Record",
            "severity": "High",
            "recommendation": "Implement a DMARC record to control SPF/DKIM "
                            "failures and receive reports.",
        }

    if policy == "none":
        rec = ("Transition to `p=quarantine` or `p=reject` after monitoring "
               "reports for legitimate mail sources.")
        return {
            "finding": "Weak DMARC Policy (p=none)",
            "severity": "Medium",
            "recommendation": rec,
        }
    return {}


def _check_caa_records(records_info: Dict[str, Any]) -> Dict[str, str]:
    """Checks for the presence of CAA records."""
    if not records_info.get("CAA"):
        return {
            "finding": "Missing CAA Record",
            "severity": "Low",
            "recommendation": "Implement CAA records to restrict which "
                            "Certificate Authorities can issue certificates for "
                            "your domain.",
        }
    return {}


def _check_zone_transfer(zone_info: Dict[str, Any]) -> Dict[str, str]:
    """Checks if a zone transfer was successful."""
    if zone_info.get("summary") == "Vulnerable (Zone Transfer Successful)":
        return {
            "finding": "Zone Transfer (AXFR) Enabled",
            "severity": "High",
            "recommendation": "Disable zone transfers to untrusted IP addresses "
                            "on your authoritative nameservers.",
        }
    return {}


def _check_dnssec(nsinfo_info: Dict[str, Any]) -> Dict[str, str]:
    """Checks for DNSSEC enablement."""
    dnssec_status = nsinfo_info.get("dnssec", "")
    if "Not Enabled" in dnssec_status:
        return {
            "finding": "DNSSEC Not Enabled",
            "severity": "Medium",
            "recommendation": "Enable DNSSEC to protect against DNS spoofing "
                            "and cache poisoning attacks.",
        }
    return {}


def _check_headers(headers_info: Dict[str, Any]) -> List[Dict[str, str]]:
    """Checks for missing or insecure HTTP security headers."""
    findings: List[Dict[str, str]] = []
    analysis = headers_info.get("analysis", {})
    for header, details in analysis.items():
        if details.get("severity") in ("High", "Critical"):
            findings.append({
                "finding": f"Insecure Header: {header}",
                "severity": details["severity"],
                "recommendation": details["recommendation"]
            })
    return findings


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
    findings = []

    # Define check functions and their required data keys
    check_map = {
        _check_spf_policy: mail_info,
        _check_dmarc_policy: mail_info,
        _check_caa_records: records_info,
        _check_zone_transfer: zone_info,
        _check_dnssec: nsinfo_info,
    }

    for check_func, data in check_map.items():
        if isinstance(data, dict) and "error" not in data and (result := check_func(data)):
            findings.append(result)

    # Header checks can return multiple findings
    if isinstance(headers_info, dict) and "error" not in headers_info:
        findings.extend(_check_headers(headers_info))

    # Sort findings by severity (Critical, High, Medium, Low)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda x: severity_order.get(x.get("severity", ""), 4))

    return {"findings": findings}