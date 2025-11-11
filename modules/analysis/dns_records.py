#!/usr/bin/env python3
import asyncio
import dns.resolver
from typing import Dict, List, Any, Optional
from ..config import console, RECORD_TYPES
from ..utils import _get_resolver, _format_rdata

async def get_dns_records(domain: str, timeout: int, verbose: bool, record_types: Optional[List[str]] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Asynchronously queries for multiple DNS record types for a given domain.
    """
    resolver = _get_resolver(timeout)
    records = {}
    
    types_to_query = record_types if record_types else RECORD_TYPES

    async def query_type(rtype: str):
        """Inner function to query a single record type."""
        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, rtype)
            record_list = []
            for rdata in answers:
                record_info = _format_rdata(rtype, rdata, answers.ttl)
                record_list.append(record_info)
            records[rtype] = record_list
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
            records[rtype] = []
            if verbose:
                console.print(f"Error querying {rtype} for {domain}: {e}")
        except dns.resolver.NoNameservers as e:
            records[rtype] = []
            if verbose:
                console.print(f"Error querying {rtype} for {domain}: {e}")

    # --- THIS BLOCK IS THE FIX ---
    # We use a sequential for loop instead of asyncio.gather()
    # to avoid being rate-limited by public DNS servers.
    for rtype in types_to_query:
        await query_type(rtype)
    # --- END OF FIX ---
    
    return records