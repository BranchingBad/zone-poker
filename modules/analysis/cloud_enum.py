#!/usr/bin/env python3
"""
Zone-Poker - Cloud Service Enumeration Module
"""
import httpx
import asyncio
import re
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

async def enumerate_cloud_services(domain: str, **kwargs) -> Dict[str, List[Dict[str, Any]]]:
    """
    Enumerates potential public cloud storage (e.g., S3 buckets, Azure Blobs) based on the domain name.
    """
    results: Dict[str, List[Dict[str, Any]]] = {"s3_buckets": [], "azure_blobs": []}
    
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

    async def check_s3_bucket(bucket_name: str, client: httpx.AsyncClient):
        url = f"http://{bucket_name}.s3.amazonaws.com"
        try:
            # A HEAD request is a lightweight way to check for existence.
            response = await client.head(url, timeout=5, follow_redirects=False)
            # A 404 status code means the bucket does not exist.
            # Other status codes (like 200, 403) indicate the bucket name is taken.
            if response.status_code != 404:
                status_code = response.status_code
                if status_code == 200:
                    status = "public"
                elif status_code == 403:
                    status = "forbidden"
                else:
                    status = "invalid"
                results["s3_buckets"].append({"url": url, "status": status})
        except httpx.RequestError as e:
            logger.debug(f"S3 check for '{bucket_name}' failed: {e}")
            # Optionally, you could record the failure:
            # results["s3_buckets"].append({"url": url, "status_code": 0, "error": str(e)})


    async def check_azure_blob(account_name: str, client: httpx.AsyncClient):
        # Azure storage account names must be 3-24 chars, lowercase letters and numbers.
        if not (3 <= len(account_name) <= 24 and account_name.isalnum()):
            return

        url = f"https://{account_name}.blob.core.windows.net"
        try:
            # A HEAD request to an existing account's base URL often returns 400 (Bad Request)
            # because a container isn't specified, which still confirms the account's existence.
            response = await client.head(url, timeout=5, follow_redirects=False)
            if response.status_code != 404:
                status_code = response.status_code
                if status_code == 200:
                    status = "public"
                elif status_code in [400, 403]:
                    status = "forbidden"
                else:
                    status = "invalid"
                results["azure_blobs"].append({"url": url, "status": status})
        except httpx.RequestError as e:
            logger.debug(f"Azure Blob check for '{account_name}' failed: {e}")
            # Optionally, you could record the failure:
            # results["azure_blobs"].append({"url": url, "status_code": 0, "error": str(e)})

    async with httpx.AsyncClient() as client:
        tasks = [check_s3_bucket(p, client) for p in permutations] + [check_azure_blob(p, client) for p in sanitized_permutations]
        await asyncio.gather(*tasks)
    
    # Sort by URL
    results["s3_buckets"].sort(key=lambda x: x['url'])
    results["azure_blobs"].sort(key=lambda x: x['url'])
    return results