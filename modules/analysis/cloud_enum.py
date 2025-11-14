#!/usr/bin/env python3
"""
Zone-Poker - Cloud Service Enumeration Module
"""
import asyncio
import logging
import re
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)


async def enumerate_cloud_services(
    domain: str, **kwargs
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Enumerates potential public cloud storage (e.g., S3 buckets, Azure Blobs) based on the domain name.
    """
    results: Dict[str, List[Dict[str, Any]]] = {"s3_buckets": [], "azure_blobs": []}

    # Generate potential bucket names from the domain
    domain_parts = domain.split(".")
    base_name = domain_parts[0]
    # Add permutation for domain without dots, e.g., 'google.ca' -> 'googleca'
    domain_no_dots = domain.replace(".", "")

    # A simple list of permutations to check
    permutations = {
        base_name,
        f"{base_name}-assets",
        f"{base_name}-prod",
        f"{base_name}-dev",
        f"{base_name}-backups",
        f"{base_name}-media",
        f"{base_name}-www",
        domain_no_dots,
        domain,
    }

    # Sanitize permutations for Azure (lowercase, alphanumeric, 3-24 chars) and remove duplicates
    sanitized_permutations = {  # noqa
        re.sub(r"[^a-z0-9]", "", p.lower()) for p in permutations
    }

    logger.debug(
        f"Checking {len(permutations)} potential S3 bucket names and "
        f"{len(sanitized_permutations)} Azure blob containers."
    )

    async def check_s3_bucket(bucket_name: str, client: httpx.AsyncClient):
        url = f"http://{bucket_name}.s3.amazonaws.com"
        try:
            # A HEAD request is a lightweight way to check for existence.
            response = await client.head(url, timeout=5, follow_redirects=False)
            # A 404 status code means the bucket does not exist.
            # Other status codes (like 200, 403) indicate the bucket name is taken.
            if response.status_code != 404:
                status = "public" if response.status_code == 200 else "forbidden"
                results["s3_buckets"].append({"url": url, "status": status})
        except httpx.RequestError as e:
            logger.debug(f"S3 check for '{bucket_name}' failed: {e}")

    async def check_azure_blob(account_name: str, client: httpx.AsyncClient):
        if not (3 <= len(account_name) <= 24 and account_name.isalnum()):
            return

        url = f"https://{account_name}.blob.core.windows.net"
        try:
            response = await client.head(url, timeout=5, follow_redirects=False)
            if response.status_code != 404:
                if response.status_code == 200:
                    status = "public"
                elif (
                    response.status_code == 400
                ):  # Azure returns 400 for valid accounts without a container
                    status = "valid_account"
                else:
                    status = "forbidden"
                results["azure_blobs"].append({"url": url, "status": status})
        except httpx.RequestError as e:
            logger.debug(f"Azure Blob check for '{account_name}' failed: {e}")

    async with httpx.AsyncClient() as client:
        tasks = [check_s3_bucket(p, client) for p in permutations] + [
            check_azure_blob(p, client) for p in sanitized_permutations
        ]
        await asyncio.gather(*tasks)

    # Sort by URL
    results["s3_buckets"].sort(key=lambda x: x["url"])
    results["azure_blobs"].sort(key=lambda x: x["url"])
    return results
