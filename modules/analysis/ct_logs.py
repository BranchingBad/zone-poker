#!/usr/bin/env python3
"""
Zone-Poker - Certificate Transparency Log Analysis Module
"""
import asyncio
import json
from typing import Any, Dict

import httpx


async def search_ct_logs(domain: str, timeout: int, **kwargs) -> Dict[str, Any]:
    """
    Searches Certificate Transparency logs for subdomains using crt.sh.
    It performs two queries: one for the wildcarded domain and one for the exact domain.
    """
    results: Dict[str, Any] = {"subdomains": [], "error": None}
    urls = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]
    headers = {"User-Agent": "Zone-Poker/1.0"}
    unique_subdomains = set()

    try:
        # Instantiate the client once and run queries concurrently for better performance.
        async with httpx.AsyncClient(timeout=timeout) as client:
            tasks = [client.get(url, headers=headers) for url in urls]
            # return_exceptions=True ensures that if one request fails, the others can still complete.
            responses = await asyncio.gather(*tasks, return_exceptions=True)

        for response in responses:
            # Process successful responses
            if isinstance(response, httpx.Response) and response.status_code == 200:
                try:
                    json_data = response.json()
                    # Handle cases where crt.sh returns an empty list for a valid domain
                    if not json_data:
                        continue
                    for entry in json_data:
                        names = entry.get("name_value", "").split("\n")
                        for name in names:
                            # Filter out wildcards, the domain itself, and ensure it's a valid subdomain
                            if (
                                name
                                and not name.startswith("*.")
                                and name.endswith(f".{domain}")
                                and name != domain
                            ):
                                unique_subdomains.add(name.lower())
                except json.JSONDecodeError:
                    # Silently ignore responses that aren't valid JSON (e.g., crt.sh error pages)
                    pass
            # Optionally, log errors from failed requests if verbose logging is enabled
            elif isinstance(response, Exception):
                # This could be expanded with logging if needed, but for now, we fail silently
                pass

        results["subdomains"] = sorted(list(unique_subdomains))
    except Exception as e:
        results["error"] = f"An unexpected error occurred: {type(e).__name__}"

    return results
