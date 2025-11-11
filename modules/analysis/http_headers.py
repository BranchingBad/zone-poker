#!/usr/bin/env python3
"""
Zone-Poker - In-depth HTTP Security Headers Analysis Module
"""
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

async def analyze_http_headers(domain: str, **kwargs) -> Dict[str, Any]:
    """
    Performs a detailed analysis of HTTP security headers.
    """
    results: Dict[str, Any] = {
        "analysis": {},
        "recommendations": [],
        "final_url": None,
        "error": None
    }
    url = f"https://{domain}"
    logger.debug(f"Analyzing HTTP headers for {url}")

    try:
        # Use verify=False to avoid SSL errors on misconfigured sites, which is common during recon
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            response = await client.get(url, timeout=10)
            response.raise_for_status()

            headers = {k.lower(): v for k, v in response.headers.items()}
            results["final_url"] = str(response.url)

            # 1. Strict-Transport-Security (HSTS)
            hsts = headers.get('strict-transport-security')
            if hsts:
                max_age_str = next((part for part in hsts.split(';') if 'max-age' in part), None)
                if max_age_str and int(max_age_str.split('=')[1].strip()) >= 31536000:
                    results["analysis"]["Strict-Transport-Security"] = {"status": "Strong", "value": hsts}
                else:
                    results["analysis"]["Strict-Transport-Security"] = {"status": "Weak", "value": hsts}
                    results["recommendations"].append("HSTS 'max-age' should be at least one year (31536000).")
            else:
                results["analysis"]["Strict-Transport-Security"] = {"status": "Missing"}
                results["recommendations"].append("Implement HSTS to enforce HTTPS.")

            # 2. Content-Security-Policy (CSP)
            csp = headers.get('content-security-policy')
            if csp:
                results["analysis"]["Content-Security-Policy"] = {"status": "Present", "value": csp}
            else:
                results["analysis"]["Content-Security-Policy"] = {"status": "Missing"}
                results["recommendations"].append("Implement a Content-Security-Policy to mitigate XSS.")

            # 3. X-Frame-Options
            xfo = headers.get('x-frame-options')
            if xfo:
                results["analysis"]["X-Frame-Options"] = {"status": "Present", "value": xfo}
            else:
                results["analysis"]["X-Frame-Options"] = {"status": "Missing"}
                results["recommendations"].append("Implement X-Frame-Options or CSP 'frame-ancestors' to prevent clickjacking.")

            # 4. X-Content-Type-Options
            xcto = headers.get('x-content-type-options')
            if xcto and xcto.lower() == 'nosniff':
                results["analysis"]["X-Content-Type-Options"] = {"status": "Present", "value": xcto}
            else:
                results["analysis"]["X-Content-Type-Options"] = {"status": "Missing or Invalid"}
                results["recommendations"].append("Set X-Content-Type-Options to 'nosniff'.")

            # 5. Referrer-Policy
            ref_policy = headers.get('referrer-policy')
            if ref_policy:
                results["analysis"]["Referrer-Policy"] = {"status": "Present", "value": ref_policy}
            else:
                results["analysis"]["Referrer-Policy"] = {"status": "Missing"}
                results["recommendations"].append("Set a Referrer-Policy to control information leakage in the Referer header.")

    except httpx.RequestError as e:
        results["error"] = f"HTTP request to {url} failed: {type(e).__name__}"
    except Exception as e:
        results["error"] = f"An unexpected error occurred: {e}"

    return results