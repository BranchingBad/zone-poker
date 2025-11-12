#!/usr/bin/env python3
import asyncio
import dns.resolver
from typing import Dict, List, Any
from ..utils import _parse_spf_record, join_txt_chunks


async def _get_spf_record(
    domain: str, resolver: dns.resolver.Resolver, depth: int = 0
) -> List[str]:
    """Recursively resolves SPF records, following redirects."""
    if depth > 10:  # RFC 7208 specifies a maximum of 10 DNS lookups
        return ["error: SPF record exceeded maximum lookup depth of 10"]
    try:
        # Prefer the dedicated SPF record type first
        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, "SPF")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Fallback to TXT if SPF type is not used
            answers = await asyncio.to_thread(resolver.resolve, domain, "TXT")

        all_txt_records = [
            join_txt_chunks([t.decode("utf-8", "ignore") for t in rdata.strings])
            for rdata in answers
        ]
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

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
        dns.name.EmptyLabel,
    ):
        return []


async def _get_dmarc_record(domain: str, resolver: dns.resolver.Resolver) -> List[str]:
    """Fetches the DMARC record from the _dmarc subdomain."""
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = await asyncio.to_thread(resolver.resolve, dmarc_domain, "TXT")
        return [
            join_txt_chunks([t.decode("utf-8", "ignore") for t in rdata.strings])
            for rdata in answers
        ]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
    ):
        return []


async def email_security_analysis(
    domain: str, resolver: dns.resolver.Resolver, **kwargs
) -> Dict[str, Any]:
    """Analyzes email security records (SPF, DMARC, DKIM) by running checks concurrently."""
    analysis: Dict[str, Any] = {}

    # Run SPF and DMARC lookups concurrently
    spf_records, dmarc_records = await asyncio.gather(
        _get_spf_record(domain, resolver), _get_dmarc_record(domain, resolver)
    )

    # --- SPF Analysis ---
    if spf_records:
        if spf_records[0].startswith("error:"):
            analysis["spf"] = {"status": "Error", "error": spf_records[0]}
        else:
            analysis["spf"] = _parse_spf_record(spf_records[0])
            if len(spf_records) > 1:
                analysis["spf"][
                    "warning"
                ] = "Multiple SPF records found. Only one is allowed."
    else:
        analysis["spf"] = {"status": "Not Found"}

    # --- DMARC Analysis ---
    if dmarc_records:
        dmarc_record_str = dmarc_records[0]
        analysis["dmarc"] = {"raw": dmarc_record_str}
        # More robustly parse DMARC tags
        for part in dmarc_record_str.split(";"):
            part = part.strip()
            if "=" in part and part.startswith("v=DMARC1"):
                continue  # Skip the version tag itself in the key-value pairs
            if "=" in part:
                key, value = part.split("=", 1)
                analysis["dmarc"][key.strip()] = value.strip()
    else:
        analysis["dmarc"] = {"status": "Not Found"}
    # DKIM (cannot be checked reliably without a selector)
    analysis["dkim"] = {
        "status": "Cannot check without selector (e.g., 'default._domainkey')"
    }

    return analysis
