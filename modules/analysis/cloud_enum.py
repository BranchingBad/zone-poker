#!/usr/bin/env python3
"""
Zone-Poker - Cloud Service Enumeration Module
"""
import httpx
import asyncio
import re
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

async def enumerate_cloud_services(domain: str, **kwargs) -> Dict[str, List[str]]:
    """
    Enumerates potential public cloud storage (e.g., S3 buckets, Azure Blobs) based on the domain name.
    """
    results: Dict[str, List[str]] = {"s3_buckets": [], "azure_blobs": []}
    
    # Generate potential bucket names from the domain
    domain_parts = domain.split('.')
    base_name = domain_parts[0]
    
    # A simple list of permutations to check
    permutations = {
        base_name,
        f"{base_name}-assets",
        f"{base_name}-prod",
        f"{base_name}-dev",
        f"{base_name}-backups",
        f"{base_name}-media",
        f"{base_name}-www",
        domain,
    }

    # Sanitize permutations for Azure (lowercase, alphanumeric, 3-24 chars)
    sanitized_permutations = {
        re.sub(r'[^a-z0-9]', '', p.lower()) for p in permutations
    }
    
    logger.debug(f"Checking {len(permutations)} potential S3 bucket names and {len(sanitized_permutations)} Azure blob containers.")

    async def check_s3_bucket(bucket_name):
        url = f"http://{bucket_name}.s3.amazonaws.com"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.head(url, timeout=5, follow_redirects=False)
                if response.status_code != 404:
                    results["s3_buckets"].append(url)
        except httpx.RequestError:
            pass # Ignore connection errors, timeouts, etc.

    async def check_azure_blob(account_name):
        # Azure storage account names must be 3-24 chars, lowercase letters and numbers.
        if not (3 <= len(account_name) <= 24 and account_name.isalnum()):
            return

        url = f"https://{account_name}.blob.core.windows.net"
        try:
            async with httpx.AsyncClient() as client:
                # A request to a non-existent storage account will fail to resolve.
                # A HEAD request to the base URL of an existing one often returns 400 (Bad Request),
                # which still indicates existence. 404 means it likely doesn't exist.
                response = await client.head(url, timeout=5, follow_redirects=False)
                if response.status_code != 404:
                    results["azure_blobs"].append(url)
        except httpx.RequestError:
            pass # Ignore connection/resolution errors

    s3_tasks = [check_s3_bucket(p) for p in permutations]
    azure_tasks = [check_azure_blob(p) for p in sanitized_permutations]
    tasks = s3_tasks + azure_tasks
    await asyncio.gather(*tasks)
    
    results["s3_buckets"].sort()
    results["azure_blobs"].sort()
    return results