#!/usr/bin/env python3
"""
Zone-Poker - Open Redirect Vulnerability Scanner
"""
import asyncio
import logging
from typing import Any, Dict
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# Payloads that might trigger an open redirect.
# The external domain should be something unlikely to be part of the target's infrastructure.
REDIRECT_PAYLOADS = [
    "//example.com",
    "/redirect?url=https://example.com",
    "/login?redirect=https://example.com",
    "/?next=https://example.com",
    "/cgi-bin/redirect.cgi?url=https://example.com",
]


async def check_open_redirect(domain: str, timeout: int, **kwargs) -> Dict[str, Any]:
    """
    Checks for basic open redirect vulnerabilities by testing common parameters.
    """
    results: Dict[str, Any] = {"vulnerable_urls": []}

    async def test_url(url: str, client: httpx.AsyncClient):
        try:
            # We must not follow redirects automatically for this check.
            response = await client.get(url, timeout=timeout, follow_redirects=False)

            # Check for 3xx redirect status codes
            if 300 <= response.status_code < 400:
                location = response.headers.get("Location", "")
                if location:
                    # Check if the redirect location points to our external test domain
                    parsed_location = urlparse(location)
                    if "example.com" in parsed_location.netloc:
                        logger.info(f"Potential open redirect found at {url}")
                        results["vulnerable_urls"].append(
                            {
                                "url": url,
                                "redirects_to": location,
                            }
                        )
        except httpx.RequestError as e:
            logger.debug(f"Open redirect check for {url} failed: {e}")

    async with httpx.AsyncClient(verify=False) as client:
        tasks = [
            test_url(f"https://{domain}{payload}", client)
            for payload in REDIRECT_PAYLOADS
        ]
        await asyncio.gather(*tasks)

    return results
