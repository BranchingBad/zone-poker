#!/usr/bin/env python3
"""
Zone-Poker - Web Application Firewall (WAF) Detection Module
"""
import httpx
from typing import Dict, Any

# A simple dictionary of common WAF fingerprints
WAF_FINGERPRINTS = {
    "Cloudflare": {"server": "cloudflare", "headers": ["__cfduid", "cf-ray"]},
    "Akamai": {"server": "AkamaiGHost", "headers": ["x-akamai-transformed"]},
    "AWS WAF": {"server": "awselb", "headers": ["x-amz-cf-id"]},
    "Sucuri": {"server": "Sucuri/Cloudproxy", "headers": ["x-sucuri-id"]},
    "Incapsula": {"headers": ["x-iinfo", "x-cdn"]},
    "Imperva": {"headers": ["x-iinfo"]},
    "Fortinet": {"headers": ["fortiwafsid"]},
    "F5 BIG-IP": {"headers": ["ts.*", "f5-irule-*"]},
}

async def detect_waf(domain: str, timeout: int, **kwargs) -> Dict[str, Any]:
    """
    Attempts to detect a Web Application Firewall (WAF) by inspecting HTTP headers.
    """
    results: Dict[str, Any] = {"detected_wafs": [], "details": {}, "error": None}
    url = f"https://{domain}"
    headers = {"User-Agent": "Zone-Poker/1.0"}

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            response = await client.get(url, headers=headers)

        response_headers = {k.lower(): v for k, v in response.headers.items()}
        server_header = response_headers.get("server", "").lower()

        for waf_name, fingerprints in WAF_FINGERPRINTS.items():
            detected = False
            if "server" in fingerprints and fingerprints["server"] in server_header:
                results["detected_wafs"].append(waf_name)
                results["details"][waf_name] = f"Server header contains '{server_header}'"
                detected = True
            
            # Check for headers only if not already detected by server header
            if not detected and any(h in response_headers for h in fingerprints.get("headers", [])):
                results["detected_wafs"].append(waf_name)
                found_headers = [h for h in fingerprints.get("headers", []) if h in response_headers]
                results["details"][waf_name] = f"Found characteristic header(s): {', '.join(found_headers)}"


    except httpx.RequestError as e:
        results["error"] = f"Could not connect to {url}: {e}"
    except Exception as e:
        results["error"] = f"An unexpected error occurred: {e}"

    return results