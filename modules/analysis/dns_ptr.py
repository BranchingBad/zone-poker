#!/usr/bin/env python3
import asyncio
import dns.resolver
import dns.reversename
from typing import Dict, List, Any

async def reverse_ptr_lookups(records: Dict[str, List[Dict[str, Any]]], resolver: dns.resolver.Resolver, **kwargs) -> Dict[str, str]:
    """
    Performs reverse DNS (PTR) lookups for all A and AAAA records found.
    """
    ptr_results = {}
    ips_to_check = []
    for rtype in ("A", "AAAA"):
        for record in records.get(rtype, []):
            if record.get("value"):
                ips_to_check.append(record["value"])

    async def query_ptr(ip):
        try:
            reversed_ip = dns.reversename.from_address(ip)
            answer = await asyncio.to_thread(resolver.resolve, reversed_ip, 'PTR')
            ptr_results[ip] = str(answer[0])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.exception.SyntaxError):
            ptr_results[ip] = "No PTR record found."
        except Exception as e:
            ptr_results[ip] = f"Error: {e}"

    # --- THIS BLOCK IS THE FIX ---
    # Use a sequential loop to avoid rate-limiting
    for ip in ips_to_check:
        if ip:
            await query_ptr(ip)
    # --- END OF FIX ---
    
    return ptr_results