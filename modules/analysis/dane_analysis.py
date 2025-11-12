#!/usr/bin/env python3
"""
Zone-Poker - DANE (TLSA) Analysis Module
"""
import asyncio
import logging
from dns.resolver import Resolver, NoAnswer, NXDOMAIN
from typing import Dict, Any

logger = logging.getLogger(__name__)


async def analyze_dane_records(
    domain: str, resolver: Resolver, **kwargs
) -> Dict[str, Any]:
    """
    Checks for DANE/TLSA records to validate TLS certificates via DNS.
    """
    results: Dict[str, Any] = {"records": [], "status": "Not Found"}
    # Check for TLSA records for HTTPS on port 443
    target = f"_443._tcp.{domain}"
    logger.debug(f"Querying TLSA records for {target}")

    try:
        answers = await asyncio.to_thread(resolver.resolve, target, "TLSA")
        tlsa_records = [str(r) for r in answers]
        if tlsa_records:
            results["records"] = tlsa_records
            results["status"] = "Present"
    except (NoAnswer, NXDOMAIN):
        results["status"] = "Not Found"
    except Exception as e:
        results["status"] = f"Error: {type(e).__name__}"

    return results
