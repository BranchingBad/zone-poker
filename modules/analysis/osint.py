#!/usr/bin/env python3
import argparse
import httpx
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


async def osint_enrichment(
    domain: str, timeout: int, verbose: bool, args: argparse.Namespace, **kwargs
) -> Dict[str, Any]:
    """
    Enriches data with passive DNS (AlienVault OTX).
    Checks for 'otx' API key in config.
    """
    osint_data = {"subdomains": [], "passive_dns": []}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"Accept": "application/json"}

    otx_key = getattr(args, "api_keys", {}).get("otx")
    if otx_key:
        headers["X-OTX-API-Key"] = otx_key
        # Use debug level for info useful for developers, not end-users.
        logger.debug("Using OTX API Key for osint_enrichment.")

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            passive_dns = data.get("passive_dns", [])
            seen_ips = set()
            for record in passive_dns:
                if record.get("address") not in seen_ips:
                    osint_data["passive_dns"].append(
                        {
                            "ip": record["address"],
                            "hostname": record["hostname"],
                            "last_seen": record["last"],
                        }
                    )
                    seen_ips.add(record["address"])

            subdomains = {
                record["hostname"]
                for record in passive_dns
                if record["hostname"].endswith(f".{domain}")
            }
            osint_data["subdomains"] = list(subdomains)
        else:
            osint_data["error"] = f"OTX query failed (Status: {response.status_code})"
    except httpx.RequestError as e:
        osint_data["error"] = f"OTX query failed: {e}"
        if verbose:
            logger.debug(f"Error during OSINT enrichment: {e}")

    return osint_data
