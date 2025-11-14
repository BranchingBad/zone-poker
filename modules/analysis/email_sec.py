#!/usr/bin/env python3
"""
Zone-Poker - Email Security Analysis Module
"""
import asyncio
from typing import Any, Dict

import dns.exception
import dns.resolver

from modules.utils import _parse_dmarc_record, _parse_spf_record, join_txt_chunks


async def email_security_analysis(
    domain: str, resolver: dns.resolver.Resolver, all_data: Dict[str, Any], **kwargs
) -> Dict[str, Any]:
    """
    Analyzes email security records (SPF, DMARC).
    DKIM is not checked as it requires selectors which are not standard.
    """
    analysis: Dict[str, Any] = {}
    records = all_data.get("records_info", {})

    # 1. Analyze SPF record from existing TXT records
    spf_records = [
        r["value"]
        for r in records.get("TXT", [])
        if r.get("value", "").startswith("v=spf1")
    ]
    if spf_records:
        analysis["spf"] = _parse_spf_record(spf_records[0])
        if len(spf_records) > 1:
            analysis["spf"][
                "warning"
            ] = "Multiple SPF records found. Only one is allowed."
    else:
        analysis["spf"] = {"status": "Not Found"}

    # 2. Analyze DMARC record
    dmarc_domain = f"_dmarc.{domain}"
    try:
        # DMARC must be queried directly as it might not be in the initial record pull
        # Use asyncio.to_thread to run the blocking call in a separate thread
        answers = await asyncio.to_thread(resolver.resolve, dmarc_domain, "TXT")
        dmarc_records = [
            join_txt_chunks([t.decode("utf-8", "ignore") for t in rdata.strings])
            for rdata in answers
        ]
        if dmarc_records:
            analysis["dmarc"] = _parse_dmarc_record(dmarc_records[0])
            # A DMARC record without a policy is not effective.
            if "p" not in analysis["dmarc"]:
                analysis["dmarc"][
                    "warning"
                ] = "DMARC record is missing the required 'p' (policy) tag."
            # Like SPF, there should only be one DMARC record.
            if len(dmarc_records) > 1:
                analysis["dmarc"][
                    "warning"
                ] = "Multiple DMARC records found. Only one is allowed."

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        analysis["dmarc"] = {"status": "Not Found"}

    # 3. DKIM - Informational
    analysis["dkim"] = {
        "status": "Cannot check without a selector (e.g., 'default._domainkey')."
    }

    return analysis
