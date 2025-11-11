#!/usr/bin/env python3
"""
Zone-Poker - In-depth HTTP Security Headers Analysis Module
"""
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# --- Centralized Header Analysis Configuration ---

def _evaluate_hsts(value: str) -> Dict[str, Any]:
    """Evaluates the Strict-Transport-Security header."""
    try:
        max_age_str = next((part for part in value.split(';') if 'max-age' in part), None)
        if max_age_str and int(max_age_str.split('=')[1].strip()) >= 31536000: # 1 year
            return {"status": "Strong", "value": value}
        return {"status": "Weak", "value": value, "recommendation": "HSTS 'max-age' should be at least one year (31536000)."}
    except (ValueError, IndexError):
        return {"status": "Invalid", "value": value, "recommendation": "HSTS 'max-age' is malformed."}

def _evaluate_xcto(value: str) -> Dict[str, Any]:
    """Evaluates the X-Content-Type-Options header."""
    if value.lower() == 'nosniff':
        return {"status": "Present", "value": value}
    return {"status": "Invalid", "value": value, "recommendation": "Set X-Content-Type-Options to 'nosniff'."}

def _evaluate_generic(value: str) -> Dict[str, Any]:
    """Generic evaluation for headers that only need to be present."""
    return {"status": "Present", "value": value}


HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "eval_func": _evaluate_hsts,
        "recommendation": "Implement HSTS to enforce HTTPS."
    },
    "Content-Security-Policy": {
        "eval_func": _evaluate_generic,
        "recommendation": "Implement a Content-Security-Policy (CSP) to mitigate XSS and other injection attacks."
    },
    "X-Frame-Options": {
        "eval_func": _evaluate_generic,
        "recommendation": "Implement X-Frame-Options or CSP 'frame-ancestors' to prevent clickjacking."
    },
    "X-Content-Type-Options": {
        "eval_func": _evaluate_xcto,
        "recommendation": "Set X-Content-Type-Options to 'nosniff' to prevent MIME-sniffing attacks."
    },
    "Referrer-Policy": {
        "eval_func": _evaluate_generic,
        "recommendation": "Set a Referrer-Policy to control information leakage in the Referer header."
    },
}

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
    urls_to_check = [f"https://{domain}", f"http://{domain}"]
    logger.debug(f"Analyzing HTTP headers for {domain}")

    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        for url in urls_to_check:
            try:
                response = await client.get(url, timeout=10)
                response.raise_for_status()

                headers = {k.lower(): v for k, v in response.headers.items()}
                results["final_url"] = str(response.url)

                for header_name, check_config in HEADER_CHECKS.items():
                    header_value = headers.get(header_name.lower())
                    if header_value:
                        analysis_result = check_config["eval_func"](header_value)
                        results["analysis"][header_name] = analysis_result
                        if "recommendation" in analysis_result:
                            results["recommendations"].append(analysis_result["recommendation"])
                    else:
                        results["analysis"][header_name] = {"status": "Missing"}
                        results["recommendations"].append(check_config["recommendation"])
                
                # If we get a successful response, we can stop.
                results["error"] = None # Clear any previous error from a failed HTTPS attempt
                return results

            except httpx.RequestError as e:
                error_message = f"HTTP request to {url} failed: {type(e).__name__}"
                results["error"] = error_message
                logger.debug(error_message)
            except Exception as e:
                results["error"] = f"An unexpected error occurred while checking {url}: {e}"

    return results