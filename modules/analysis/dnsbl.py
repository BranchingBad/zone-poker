#!/usr/bin/env python3
"""
Zone-Poker - DNSBL (DNS-based Blocklist) Analysis Module
"""
import asyncio
import dns.resolver
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

# A list of common DNSBL services
DNSBL_PROVIDERS = [
    "zen.spamhaus.org",
    "spam.dnsbl.sorbs.net",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "b.barracudacentral.org",
]

async def check_dnsbl(records_info: Dict[str, List[Dict[str, Any]]], resolver: dns.resolver.Resolver, **kwargs) -> Dict[str, Any]:
    """
    Checks IP addresses from A/AAAA records against common DNSBL services.
    """
    results: Dict[str, List[Dict]] = {"listed_ips": []}
    
    # Collect all unique IP addresses from A and AAAA records
    a_records = records_info.get("A", [])
    aaaa_records = records_info.get("AAAA", [])
    all_ips = list(set([rec.get("value") for rec in a_records + aaaa_records if rec.get("value")]))

    if not all_ips:
        return results

    logger.debug(f"Checking {len(all_ips)} IP addresses against {len(DNSBL_PROVIDERS)} DNSBL providers.")

    async def check_ip(ip: str) -> Dict[str, Any] | None:
        """Checks a single IP against all DNSBL providers."""
        listed_on = []
        reversed_ip = ".".join(reversed(ip.split(".")))

        for provider in DNSBL_PROVIDERS:
            query = f"{reversed_ip}.{provider}"
            try:
                await asyncio.to_thread(resolver.resolve, query, "A")
                listed_on.append(provider)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue # Not listed
            except Exception as e:
                logger.debug(f"DNSBL query for {query} failed: {e}")
        
        if listed_on:
            return {"ip": ip, "listed_on": listed_on}
        return None

    tasks = [check_ip(ip) for ip in all_ips]
    task_results = await asyncio.gather(*tasks)
    results["listed_ips"] = [res for res in task_results if res is not None]
    return results