#!/usr/bin/env python3
import httpx
import hashlib
import codecs
import mmh3
from typing import Dict, Any

async def get_content_hashes(domain: str, timeout: int, **kwargs) -> Dict[str, Any]:
    """
    Fetches the favicon and main page to calculate their MurmurHash3 and SHA256 hashes.
    """
    results: Dict[str, Any] = {"error": None}
    headers = {"User-Agent": "Zone-Poker/1.0"}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        # 1. Favicon Hashing (MurmurHash3 for Shodan compatibility)
        try:
            favicon_url = f"https://{domain}/favicon.ico"
            response = await client.get(favicon_url, headers=headers)
            
            if response.status_code == 200 and response.content:
                # Standard favicon hash used by Shodan
                favicon_b64 = codecs.encode(response.content, 'base64')
                murmur_hash = mmh3.hash(favicon_b64)
                results["favicon_murmur32_hash"] = str(murmur_hash)
        except httpx.RequestError as e:
            # This is a common, non-critical error, so we won't pollute the main error field
            results["favicon_error"] = f"Could not fetch favicon: {type(e).__name__}"

        # 2. Page Content Hashing (SHA256 for identifying duplicates)
        try:
            page_url = f"https://{domain}"
            response = await client.get(page_url, headers=headers)
            if response.status_code == 200 and response.content:
                results["page_sha256_hash"] = hashlib.sha256(response.content).hexdigest()
        except httpx.RequestError as e:
            results["error"] = f"Could not fetch main page: {type(e).__name__}"

    return results