#!/usr/bin/env python3
import asyncio
import dns.resolver
import logging
from typing import Dict, List, Any, Optional
from ..config import RECORD_TYPES
from ..utils import _format_rdata
 
logger = logging.getLogger(__name__)

async def get_dns_records(domain: str, resolver: dns.resolver.Resolver, verbose: bool, record_types: Optional[List[str]] = None, **kwargs) -> Dict[str, List[Dict[str, Any]]]:
    """
    Asynchronously queries for multiple DNS record types for a given domain.
    """

    records = {}
    
    types_to_query = record_types if record_types else RECORD_TYPES

    # Use a semaphore to limit concurrent requests to avoid rate-limiting
    sem = asyncio.Semaphore(10)

    async def query_type(rtype: str) -> None:
        """Inner function to query a single record type."""
        async with sem:
            try:
                answers = await asyncio.to_thread(resolver.resolve, domain, rtype)
                record_list = []
                for rdata in answers:
                    record_info = _format_rdata(rtype, rdata, answers.ttl, name=str(answers.qname))
                    record_list.append(record_info)
                records[rtype] = record_list
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
                records[rtype] = []
                logger.debug(f"DNS query for {rtype} on {domain} failed: {e}")
            except dns.resolver.NoNameservers as e:
                records[rtype] = []
                logger.debug(f"DNS query for {rtype} on {domain} failed (No Nameservers): {e}")

    # Create and run all query tasks concurrently
    tasks = [query_type(rtype) for rtype in types_to_query]
    await asyncio.gather(*tasks)
    
    return records