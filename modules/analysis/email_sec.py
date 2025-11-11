#!/usr/bin/env python3
import asyncio
import dns.resolver
from typing import Dict, List, Any
from ..utils import _parse_spf_record, join_txt_chunks

async def _get_spf_record(domain: str, resolver: dns.resolver.Resolver, depth=0) -> List[str]:
    """Recursively resolves SPF records, following redirects."""
    if depth > 5:  # Prevent infinite recursion
        return []
    try:
        # Prefer the dedicated SPF record type first
        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, "SPF")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Fallback to TXT if SPF type is not used
            answers = await asyncio.to_thread(resolver.resolve, domain, "TXT")

        all_txt_records = [join_txt_chunks([t.decode('utf-8', 'ignore') for t in rdata.strings]) for rdata in answers]
        spf_records = [r for r in all_txt_records if r.startswith("v=spf1")]

        if not spf_records:
            return []

        # Check for a redirect in the first found SPF record
        spf_record = spf_records[0]
        if "redirect=" in spf_record:
            redirect_domain = spf_record.split("redirect=")[1].split(" ")[0]
            return await _get_spf_record(redirect_domain, resolver, depth + 1)
        else:
            return spf_records

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers, dns.name.EmptyLabel):
        return []

async def email_security_analysis(domain: str, records: Dict[str, List[Dict[str, Any]]], resolver: dns.resolver.Resolver, **kwargs) -> Dict[str, Any]:
    """Analyzes email security records (SPF, DMARC, DKIM)."""
    analysis = {}

    # --- SPF Check (ENHANCED) ---
    # Recursively resolve SPF records to handle redirects.
    spf_records = await _get_spf_record(domain, resolver)

    if spf_records:
        analysis["spf"] = _parse_spf_record(spf_records[0])
        if len(spf_records) > 1:
            analysis["spf"]["warning"] = "Multiple SPF records found. Only one is allowed."
    else:
        analysis["spf"] = {"status": "Not Found"}
    
    # --- DMARC Check ---
    # Always query the _dmarc subdomain directly.
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = []
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