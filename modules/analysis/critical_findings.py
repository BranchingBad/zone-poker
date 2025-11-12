#!/usr/bin/env python3
"""
Zone-Poker - Critical Findings Aggregator
This module centralizes the logic for identifying high-impact security issues.
"""
import datetime
from typing import Dict, Any, List

# A data-driven structure defining each critical check.
# Each check has a 'condition' lambda that returns True if the finding is critical,
# and a 'message' lambda to format the output string.
CRITICAL_CHECKS = [
    {
        "name": "Zone Transfer",
        "condition": lambda data: "Vulnerable" in data.get("zone_info", {}).get("summary", ""),
        "message": lambda data: "Zone Transfer Successful (AXFR): Domain is vulnerable to full zone enumeration.",
    },
    {
        "name": "Subdomain Takeover",
        "condition": lambda data: data.get("takeover_info", {}).get("vulnerable"),
        "message": lambda data: (
            f"Subdomain Takeover: Found {len(data['takeover_info']['vulnerable'])} "
            "potentially vulnerable subdomains."
        ),
    },
    {
        "name": "Expired SSL Certificate",
        "condition": lambda data: (
            data.get("ssl_info", {}).get("valid_until") and
            datetime.datetime.now().timestamp() > data["ssl_info"]["valid_until"]
        ),
        "message": lambda data: "Expired SSL/TLS Certificate: The main web server's certificate has expired.",
    },
    {
        "name": "High-Risk IP Reputation",
        "condition": lambda data: any(
            isinstance(info, dict) and info.get("abuseConfidenceScore", 0) > 75
            for info in data.get("reputation_info", {}).values()
        ),
        "message": lambda data: (
            f"High-Risk IP Reputation: {len([ip for ip, info in data['reputation_info'].items() if isinstance(info, dict) and info.get('abuseConfidenceScore', 0) > 75])} "
            f"IP(s) have a high abuse score."
        ),
    },
    {
        "name": "Overly Permissive SPF Policy",
        "condition": lambda data: data.get("mail_info", {}).get("spf", {}).get("all_policy") == "+all",
        "message": lambda data: "Overly Permissive SPF Policy (+all): The SPF record allows anyone to send email on your behalf.",
    },
]


def aggregate_critical_findings(all_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    """
    Evaluates all defined critical checks against the scan data.

    This function iterates through CRITICAL_CHECKS, evaluates the condition for each,
    and collects the formatted messages for any that are met.

    Args:
        all_data: The main dictionary containing all scan results.

    Returns:
        A dictionary containing a list of critical finding messages.
    """
    findings = []
    for check in CRITICAL_CHECKS:
        try:
            # Check if the data required for the condition exists and is not an error
            if check["condition"](all_data):
                findings.append(check["message"](all_data))
        except (KeyError, TypeError, IndexError):
            # Gracefully skip a check if its required data is missing or malformed
            continue

    return {"critical_findings": findings}