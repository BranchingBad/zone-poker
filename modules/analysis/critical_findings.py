#!/usr/bin/env python3
"""
Zone-Poker - Critical Findings Aggregator
This module centralizes the logic for identifying high-impact security issues.
"""
from typing import Any, Dict


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
        if severity in ("Critical", "High"):  # Check for Critical or High severity
            # Ensure 'finding' and 'recommendation' are present before formatting
            finding_text = finding.get("finding", "Unknown Finding")
            recommendation_text = finding.get(
                "recommendation", "No specific recommendation provided."
            )
            message = f"{finding_text}: {recommendation_text}"
            critical_findings.append(message)  # Add the formatted message to the list

    return {"critical_findings": critical_findings}
