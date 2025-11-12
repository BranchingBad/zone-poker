#!/usr/bin/env python3
import asyncio
import dns.resolver
import dns.reversename
from typing import Dict, List, Any

async def reverse_ptr_lookups(resolver: dns.resolver.Resolver, records_info: Dict[str, List[Dict[str, Any]]], **kwargs) -> Dict[str, List[Dict[str, str]]]:
    """
    Performs reverse DNS (PTR) lookups for all A and AAAA records found.
    """
    ptr_results: Dict[str, List[Dict[str, str]]] = {"ptr_records": []}
    ips_to_check = []
    for rtype in ("A", "AAAA"):
        for record in records_info.get(rtype, []):
            if record.get("value"):
                ips_to_check.append(record["value"])

    # Use a semaphore to limit concurrent PTR queries to avoid rate-limiting
    sem = asyncio.Semaphore(10)

    async def query_ptr(ip: str) -> Dict[str, str] | None:
        """Inner function to query a single PTR record."""
        try:
            async with sem:
                reversed_ip = dns.reversename.from_address(ip)
                answer = await asyncio.to_thread(resolver.resolve, reversed_ip, 'PTR')
                return {"ip": ip, "hostname": str(answer[0])}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.exception.SyntaxError):
            # We can optionally include IPs that didn't resolve
            return {"ip": ip, "hostname": "No PTR record found."}
        except Exception as e:
            return {"ip": ip, "hostname": f"Error: {e}"}
        return None

    # Create and run all query tasks concurrently
    tasks = [query_ptr(ip) for ip in set(ips_to_check) if ip]
    task_results = await asyncio.gather(*tasks)
    ptr_results["ptr_records"] = [res for res in task_results if res is not None]

    return ptr_results