#!/usr/bin/env python3
import asyncio
import dns.resolver
from typing import Dict, List, Any, Optional
import logging
from ..config import RECORD_TYPES
from ..utils import _format_rdata

logger = logging.getLogger(__name__)


async def get_dns_records(
    domain: str,
    resolver: dns.resolver.Resolver,
    verbose: bool,
    record_types: Optional[List[str]] = None,
    **kwargs,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Asynchronously queries for multiple DNS record types for a given domain.
    """

    records = {}

    async def query_type(rtype: str):
        """Inner function to query a single record type."""
        try:
            answers = await asyncio.to_thread(resolver.resolve, domain, rtype)
            record_list = []
            for rdata in answers:
                record_info = _format_rdata(
                    rtype, rdata, answers.ttl, name=str(answers.qname)
                )
                record_list.append(record_info)
            records[rtype] = record_list
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
        ) as e:
            records[rtype] = []
            if verbose:
                logger.debug(f"Error querying {rtype} for {domain}: {e}")
        except dns.resolver.NoNameservers as e:
            records[rtype] = []
            if verbose:
                logger.debug(f"Error querying {rtype} for {domain}: {e}")

    # We use a sequential for loop here instead of asyncio.gather() to avoid potential
    # rate-limiting issues from DNS servers when sending many concurrent requests.
    for rtype in record_types or RECORD_TYPES:
        await query_type(rtype)

    return records
