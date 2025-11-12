#!/usr/bin/env python3
"""
Zone-Poker - Certificate Transparency Log Analysis Module
"""
import httpx
from typing import Dict, Any


async def search_ct_logs(domain: str, timeout: int, **kwargs) -> Dict[str, Any]:
    """
    Searches Certificate Transparency logs for subdomains using crt.sh.
    """
    results: Dict[str, Any] = {"subdomains": [], "error": None}
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Zone-Poker/1.0"}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()

        unique_subdomains = set()
        for entry in response.json():
            names = entry.get("name_value", "").split("\n")
            for name in names:
                # Filter out wildcards, the domain itself, and ensure it's a valid subdomain
                if (
                    name
                    and not name.startswith("*.")
                    and name.endswith(f".{domain}")
                    and name != domain
                ):
                    unique_subdomains.add(name)

        results["subdomains"] = sorted(list(unique_subdomains))

    except httpx.RequestError as e:
        results["error"] = f"crt.sh query failed: {e}"
    except Exception as e:
        results["error"] = f"An unexpected error occurred: {e}"

    return results
