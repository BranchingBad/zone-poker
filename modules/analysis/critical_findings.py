#!/usr/bin/env python3
"""
Zone-Poker - Critical Findings Aggregator
This module centralizes the logic for identifying high-impact security issues.
"""
from typing import Dict, Any


def aggregate_critical_findings(all_data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
    """
    Aggregates 'Critical' and 'High' severity findings from the security_audit module.

    Args:
        all_data: The main dictionary containing all scan results.

    Returns:
        A dictionary containing a list of critical finding messages.
    """
    critical_findings = []
    security_findings = all_data.get("security_info", {}).get("findings", [])

    for finding in security_findings:
        severity = finding.get("severity")
        if severity in ("Critical", "High"):
            message = f"{finding.get('finding')}: {finding.get('recommendation')}"
            critical_findings.append(message)

    return {"critical_findings": critical_findings}
