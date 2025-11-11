#!/usr/bin/env python3
import asyncio
import dns.resolver
from typing import Dict, List, Any
from ..utils import _parse_spf_record, join_txt_chunks

async def email_security_analysis(domain: str, records: Dict[str, List[Dict[str, Any]]], resolver: dns.resolver.Resolver) -> Dict[str, Any]:
    """Analyzes email security records (SPF, DMARC, DKIM)."""
    analysis = {}

    # SPF (No network call needed, uses existing records)
    spf_records = [r["value"] for r in records.get("TXT", []) if r["value"].startswith("v=spf1")]
    if spf_records:
        analysis["spf"] = _parse_spf_record(spf_records[0])
        if len(spf_records) > 1:
            analysis["spf"]["warning"] = "Multiple SPF records found. Only one is allowed."
    else:
        analysis["spf"] = {"status": "Not Found"}

    # DMARC
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = [r["value"] for r in records.get("TXT", []) if r.get("value", "").startswith("v=DMARC1")]
    
    # If not on root, check the _dmarc subdomain asynchronously
    if not dmarc_records:
         try:
            answers = await asyncio.to_thread(resolver.resolve, dmarc_domain, "TXT")
            dmarc_records = [join_txt_chunks([t.decode('utf-8', 'ignore') for t in rdata.strings]) for rdata in answers]
         except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            dmarc_records = []
    
    if dmarc_records:
        analysis["dmarc"] = {"raw": dmarc_records[0]}
        for part in dmarc_records[0].split(";"):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                analysis["dmarc"][key] = value
    else:
        analysis["dmarc"] = {"status": "Not Found"}

    # DKIM (cannot be checked reliably without a selector)
    analysis["dkim"] = {"status": "Cannot check without selector (e.g., 'default._domainkey')"}

    return analysis