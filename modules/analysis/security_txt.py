#!/usr/bin/env python3
"""
Zone-Poker - security.txt Analysis Module
This module checks for the presence and content of a security.txt file.
"""

from typing import Any, Dict, List

import httpx


async def check_security_txt(domain: str, timeout: int, **kwargs) -> Dict[str, Any]:
    """
    Checks for a security.txt file at standard locations (.well-known/security.txt
    and /security.txt) and parses its content.

    Args:
        domain: The domain to check.

    Returns:
        A dictionary containing the analysis results.
    """
    # Per RFC 9116, check the .well-known path first, then the root.
    urls_to_check: List[str] = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt",
    ]
    results: Dict[str, Any] = {"found": False, "url": None, "parsed": {}}

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        for url in urls_to_check:
            try:
                response = await client.get(url, follow_redirects=True)

                # If we get a successful response, parse it and stop checking other URLs.
                if response.status_code == 200:
                    results["found"] = True
                    results["url"] = str(response.url)
                    content = response.text

                    # Basic parser for security.txt fields
                    parsed_content: Dict[str, Any] = {}
                    for line in content.splitlines():
                        if line.startswith("#") or ":" not in line:
                            continue
                        key, value = line.split(":", 1)
                        key = key.strip()
                        value = value.strip()
                        if key in parsed_content:
                            if not isinstance(parsed_content[key], list):
                                parsed_content[key] = [parsed_content[key]]
                            parsed_content[key].append(value)
                        else:
                            parsed_content[key] = value
                    results["parsed"] = parsed_content
                    return results  # Found and parsed, so we are done.

            except httpx.RequestError as e:
                results["error"] = f"Request to {url} failed: {e.__class__.__name__}"
                # Continue to the next URL if one fails

    return results
