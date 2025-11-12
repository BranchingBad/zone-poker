#!/usr/bin/env python3
import asyncio
import dns.resolver
import dns.reversename
from typing import Dict, List, Any


async def reverse_ptr_lookups(
    resolver: dns.resolver.Resolver,
    records_info: Dict[str, List[Dict[str, Any]]],
    **kwargs,
) -> Dict[str, str]:
    """
    Performs reverse DNS (PTR) lookups for all A and AAAA records found.
    """
    ptr_results = {}
    ips_to_check = []
    for rtype in ("A", "AAAA"):
        for record in records_info.get(rtype, []):
            if record.get("value"):
                ips_to_check.append(record["value"])

    # Use a semaphore to limit concurrent PTR queries to avoid rate-limiting
    sem = asyncio.Semaphore(10)

    async def query_ptr(ip: str):
        """Inner function to query a single PTR record."""
        try:
            async with sem:
                reversed_ip = dns.reversename.from_address(ip)
                answer = await asyncio.to_thread(resolver.resolve, reversed_ip, "PTR")
                ptr_results[ip] = str(answer[0])
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
            dns.exception.SyntaxError,
        ):
            ptr_results[ip] = "No PTR record found."
        except Exception as e:
            ptr_results[ip] = f"Error: {e}"

    # Create and run all query tasks concurrently
    tasks = [query_ptr(ip) for ip in set(ips_to_check) if ip]
    await asyncio.gather(*tasks)

    return ptr_results
