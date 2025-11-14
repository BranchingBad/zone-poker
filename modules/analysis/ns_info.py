#!/usr/bin/env python3
import asyncio
import logging
from typing import Any, Dict, List

import dns.resolver
from ipwhois import IPWhois, exceptions

logger = logging.getLogger(__name__)


async def _resolve_ns_ips(resolver: dns.resolver.Resolver, ns_name: str, rtype: str) -> List[str]:
    """Helper to resolve A or AAAA records for a nameserver."""
    try:
        answers = await asyncio.to_thread(resolver.resolve, ns_name, rtype)
        return [str(a) for a in answers]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
    ):
        return []


async def _analyze_single_ns(resolver: dns.resolver.Resolver, verbose: bool, ns_name: str) -> Dict[str, Any]:
    """Analyzes a single nameserver, returning its information."""
    info: Dict[str, Any] = {"ips": []}

    # Concurrently resolve A and AAAA records
    a_records, aaaa_records = await asyncio.gather(
        _resolve_ns_ips(resolver, ns_name, "A"),
        _resolve_ns_ips(resolver, ns_name, "AAAA"),
    )
    ns_ips = a_records + aaaa_records

    if not ns_ips:
        info["error"] = "No A or AAAA records found for NS"
        return info

    info["ips"] = ns_ips
    first_ip = ns_ips[0]

    try:
        obj = IPWhois(first_ip)
        # Run the blocking RDAP lookup in a thread
        ip_whois_data = await asyncio.to_thread(obj.lookup_rdap, inc_raw=False)

        if ip_whois_data:
            info["asn"] = ip_whois_data.get("asn", "N/A")
            info["asn_registry"] = ip_whois_data.get("asn_registry", "N/A")
            info["asn_cidr"] = ip_whois_data.get("asn_cidr", "N/A")
            info["asn_description"] = ip_whois_data.get("asn_description", "N/A")
    except exceptions.IPDefinedError:
        info["asn_description"] = "Private IP Address"
    except Exception as e:
        info["error"] = f"RDAP lookup failed: {type(e).__name__}"
        if verbose:
            logger.debug(f"Error analyzing NS {ns_name}: {e}")

    return info


async def nameserver_analysis(
    resolver: dns.resolver.Resolver,
    verbose: bool,
    records_info: Dict[str, List[Dict[str, Any]]],
    **kwargs,
) -> Dict[str, Any]:
    """Analyzes nameservers, checking IPs (A and AAAA) and DNSSEC support."""
    results: Dict[str, Any] = {}
    ns_records = records_info.get("NS", [])
    if not ns_records:
        return {"error": "No NS records found."}

    # Create concurrent analysis tasks for all nameservers
    tasks = {ns["value"]: _analyze_single_ns(resolver, verbose, ns["value"]) for ns in ns_records}
    analysis_results = await asyncio.gather(*tasks.values())

    for ns_name, result_data in zip(tasks.keys(), analysis_results):
        results[ns_name] = result_data

    # Check DNSSEC
    if records_info.get("DNSKEY") and records_info.get("DS"):
        results["dnssec"] = "Enabled (DNSKEY and DS records found)"
    elif records_info.get("DNSKEY"):
        results["dnssec"] = "Partial (DNSKEY found, but no DS record)"
    else:
        results["dnssec"] = "Not Enabled (No DNSKEY or DS records)"

    return results
