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
    "Amazon S3": ["the specified bucket does not exist"],
    "GitHub Pages": ["there isn't a github pages site here."],
    "Heroku": ["no such app"],
    "Shopify": ["sorry, this shop is currently unavailable."],
    "Fastly": ["fastly error: unknown domain"],
    "Ghost": ["the thing you were looking for is no longer here, or never was"],
    "Bitbucket": ["repository not found"],
    "Surge.sh": ["project not found"],
    "Netlify": ["not found"],
    "Campaign Monitor": ["trying to access your account?"],
    "Readme.io": ["project not found"],
    "UserVoice": ["this uservoice instance is not available."],
    "Kajabi": ["404 not found"],
    "Intercom": ["this page is reserved for a new intercom app."],
}

async def check_subdomain_takeover(records: Dict[str, List[Dict[str, Any]]], **kwargs) -> Dict[str, Any]:
    """
    Checks for potential subdomain takeovers via dangling CNAME records.
    """
    cname_records = records.get("CNAME", [])

    if not cname_records:
        return {"vulnerable": []}
    
    results: Dict[str, Any] = {"vulnerable": []}
    logger.debug(f"Checking {len(cname_records)} CNAME records for takeover vulnerabilities.")

    async def check_cname(record: Dict[str, Any], client: httpx.AsyncClient) -> Dict[str, Any] | None:
        subdomain = record.get("name")
        if not subdomain:
            return None

        # Check both HTTP and HTTPS
        for scheme in ["http", "https"]:
            url = f"{scheme}://{subdomain}"
            try:
                response = await client.get(url, timeout=10)
                response_text_lower = response.text.lower()
                for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
                    for fingerprint in fingerprints:
                        if fingerprint in response_text_lower:
                            return {
                                "subdomain": subdomain,
                                "cname_target": record.get("value"),
                                "service": service,
                                "protocol": scheme,
                            }
            except httpx.RequestError as e:
                logger.debug(f"Subdomain takeover check for {url} failed: {e}")
        return None

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        tasks = [check_cname(rec, client) for rec in cname_records]
        task_results = await asyncio.gather(*tasks)

    # Aggregate results after all tasks are complete
    results["vulnerable"] = [res for res in task_results if res is not None]
    return results