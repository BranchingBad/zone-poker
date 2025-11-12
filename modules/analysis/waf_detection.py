#!/usr/bin/env python3
"""
Zone-Poker - WAF Detection Module
"""
from typing import Dict, Any

import httpx


async def detect_waf(
    domain: str,
    timeout: int,
    **kwargs: Any
) -> Dict[str, Any]:
    """
    Attempts to identify a Web Application Firewall by sending a malicious-like
    payload and observing the server's response.
    """
    waf_info = {"detected_waf": "None", "reason": ""}
    malicious_payload = "/?s=<script>alert('xss')</script>"
    url = f"https://{domain}{malicious_payload}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            headers=headers
        ) as client:
            response = await client.get(url)

            # Simple checks based on response headers and status code
            if response.status_code in (403, 406, 429):
                waf_info["detected_waf"] = "Generic WAF/Block"
                waf_info["reason"] = f"Blocked with status code {response.status_code}."
            if "cloudflare" in response.headers.get("Server", "").lower():
                waf_info["detected_waf"] = "Cloudflare"
                waf_info["reason"] = "Server header indicates Cloudflare."
            if "incapsula" in str(response.headers).lower():
                waf_info["detected_waf"] = "Imperva Incapsula"
                waf_info["reason"] = "Incapsula headers detected."

    except httpx.RequestError:
        waf_info["reason"] = "Could not connect to the server to perform the check."

    return waf_info