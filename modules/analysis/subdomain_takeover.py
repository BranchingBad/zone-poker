#!/usr/bin/env python3
"""
Zone-Poker - Subdomain Takeover Detection Module
"""
import asyncio
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)


@lru_cache(maxsize=None)
def _load_fingerprints() -> dict:
    """Loads takeover fingerprints from the JSON file."""
    try:
        fingerprint_path = Path(__file__).parent / "takeover_fingerprints.json"
        with open(fingerprint_path, "r") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.warning(
            f"Could not load takeover fingerprints file (takeover_fingerprints.json): {e}. Takeover scan will be skipped."
        )
        return {}


async def check_subdomain_takeover(
    records_info: Dict[str, List[Dict[str, Any]]], **kwargs
) -> Dict[str, Any]:
    """
    Checks for potential subdomain takeovers by matching CNAME records against a list
    of vulnerable services and their fingerprints.
    """
    cname_records = records_info.get("CNAME", []) or []
    takeover_fingerprints = _load_fingerprints()

    if (
        not cname_records
        or not takeover_fingerprints
        or not isinstance(cname_records, list)
    ):
        return {"vulnerable": []}

    results: Dict[str, Any] = {"vulnerable": []}
    logger.debug(
        f"Checking {len(cname_records)} CNAME records for takeover vulnerabilities."
    )

    async def check_record(
        record: Dict[str, Any], client: httpx.AsyncClient
    ) -> Dict[str, Any] | None:
        subdomain = record.get("name")
        cname_target = record.get("value")

        if not subdomain or not cname_target:
            return None

        # Find a matching service based on the CNAME target
        for service, details in takeover_fingerprints.items():
            service_cnames = details.get("cname", [])
            # Check if the CNAME target ends with any of the known vulnerable service CNAMEs
            if any(cname_target.endswith(sc) for sc in service_cnames):
                # If it matches, now check for fingerprints via HTTP/S
                for scheme in ["http", "https"]:
                    url = f"{scheme}://{subdomain}"
                    try:
                        response = await client.get(url, timeout=10)
                        response_text_lower = response.text.lower()
                        fingerprints = details.get("fingerprints", [])
                        for fingerprint in fingerprints:
                            if fingerprint.lower() in response_text_lower:
                                logger.info(
                                    f"Potential takeover found for {subdomain} pointing to {service}"
                                )
                                return {
                                    "subdomain": subdomain,
                                    "cname_target": cname_target,
                                    "service": service,
                                    "protocol": scheme,
                                }
                    except httpx.RequestError as e:
                        logger.debug(f"Subdomain takeover check for {url} failed: {e}")
                # If we found a CNAME match but no fingerprint, we can stop checking this record against other services.
                break
        return None

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=10
    ) as client:
        tasks = [check_record(rec, client) for rec in cname_records]
        task_results = await asyncio.gather(*tasks)

    # Filter out None results and aggregate
    results["vulnerable"] = [res for res in task_results if res is not None]
    return results
