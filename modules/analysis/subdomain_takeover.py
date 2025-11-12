#!/usr/bin/env python3
"""
Zone-Poker - Subdomain Takeover Detection Module
"""
import httpx
import json
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def _load_fingerprints() -> Dict:
    """Loads takeover fingerprints from the JSON file."""
    try:
        fingerprint_path = Path(__file__).parent / "takeover_fingerprints.json"
        with open(fingerprint_path, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load takeover fingerprints: {e}")
        return {}

async def check_subdomain_takeover(records_info: Dict[str, List[Dict[str, Any]]], **kwargs) -> Dict[str, Any]:
    """
    Checks for potential subdomain takeovers via dangling CNAME records.
    """
    cname_records = records_info.get("CNAME", [])

    takeover_fingerprints = _load_fingerprints()

    if not cname_records or not isinstance(cname_records, list):
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
                for service, details in takeover_fingerprints.items():
                    fingerprints = details.get("fingerprints", [])
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

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
        tasks = [check_cname(rec, client) for rec in cname_records]
        task_results = await asyncio.gather(*tasks)

    # Filter out None results and aggregate
    results["vulnerable"] = [res for res in task_results if res is not None]
    return results