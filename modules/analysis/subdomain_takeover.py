#!/usr/bin/env python3
"""
Zone-Poker - Subdomain Takeover Detection Module
"""
import httpx
import asyncio
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

# A dictionary of fingerprints for common vulnerable services
TAKEOVER_FINGERPRINTS = {
    "Amazon S3": "The specified bucket does not exist",
    "GitHub Pages": "There isn't a GitHub Pages site here.",
    "Heroku": "No such app",
    "Shopify": "Sorry, this shop is currently unavailable.",
    "Fastly": "Fastly error: unknown domain",
    "Ghost": "The thing you were looking for is no longer here, or never was",
    "Bitbucket": "Repository not found",
    "Surge.sh": "project not found",
    "Netlify": "Not Found",
}

async def check_subdomain_takeover(records: Dict[str, List[Dict[str, Any]]], **kwargs) -> Dict[str, List[Dict]]:
    """
    Checks for potential subdomain takeovers via dangling CNAME records.
    """
    results: Dict[str, List[Dict]] = {"vulnerable": []}
    cname_records = records.get("CNAME", [])

    if not cname_records:
        return results

    logger.debug(f"Checking {len(cname_records)} CNAME records for takeover vulnerabilities.")

    async def check_cname(record):
        subdomain = record.get("name")
        if not subdomain:
            return

        # Check both HTTP and HTTPS
        for scheme in ["http", "https"]:
            url = f"{scheme}://{subdomain}"
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
                    response = await client.get(url, timeout=10)
                    for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                        if fingerprint in response.text:
                            results["vulnerable"].append({
                                "subdomain": subdomain,
                                "cname_target": record.get("value"),
                                "service": service,
                            })
                            return # Found a vulnerability, no need to check further
            except httpx.RequestError as e:
                logger.debug(f"Subdomain takeover check for {url} failed: {e}")

    tasks = [check_cname(rec) for rec in cname_records]
    await asyncio.gather(*tasks)
    return results