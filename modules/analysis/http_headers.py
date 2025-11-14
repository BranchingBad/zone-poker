#!/usr/bin/env python3
"""
Zone-Poker - In-depth HTTP Security Headers Analysis Module
"""

import logging
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

# --- Centralized Header Analysis Configuration ---


def _evaluate_hsts(value: str) -> Dict[str, Any]:
    """Evaluates the Strict-Transport-Security header."""
    directives = {p.strip().lower() for p in value.split(";")}
    has_subdomains = "includesubdomains" in directives
    has_preload = "preload" in directives
    recommendations = []
    max_age = -1  # Use -1 to indicate not found

    try:
        # Find and parse max-age more robustly
        for part in directives:
            if part.startswith("max-age="):
                max_age = int(part.split("=")[1])
                break

        if max_age == 0:
            return {
                "status": "Disabled",
                "value": value,
                "recommendation": "HSTS is explicitly disabled with max-age=0.",
            }
        if max_age == -1:
            return {
                "status": "Invalid",
                "value": value,
                "recommendation": "HSTS header is present but missing the required 'max-age' directive.",
            }
    except (ValueError, IndexError):
        return {
            "status": "Invalid",
            "value": value,
            "recommendation": "HSTS 'max-age' is malformed.",
        }

    # Recommendations based on parsed values
    if max_age < 31536000:  # 1 year
        recommendations.append("HSTS 'max-age' is less than one year (31536000 seconds).")
    if not has_subdomains:
        recommendations.append("HSTS is missing the 'includeSubDomains' directive, which is required for preloading.")
    if not has_preload and has_subdomains and max_age >= 31536000:
        recommendations.append("The policy is eligible for HSTS preloading. Consider adding the 'preload' directive.")

    status = "Strong" if max_age >= 31536000 and has_subdomains else "Weak"
    return {
        "status": status,
        "value": value,
        "recommendation": " ".join(recommendations),
    }


def _evaluate_csp(value: str) -> Dict[str, Any]:
    """Performs a more comprehensive evaluation of the Content-Security-Policy header."""
    recommendations = []
    is_weak = False

    # Parse the CSP into a dictionary of directives and their sources
    directives = {}
    for directive_part in value.split(";"):
        parts = directive_part.strip().split()
        if not parts:
            continue
        directive_name = parts[0].lower()
        sources = [p.lower() for p in parts[1:]]
        directives[directive_name] = sources

    # --- Check for common weaknesses ---
    script_src = directives.get("script-src", directives.get("default-src", []))
    object_src = directives.get("object-src", directives.get("default-src", []))

    if "'unsafe-inline'" in script_src:
        is_weak = True
        # Check if it's mitigated by a nonce or hash
        if not any(s.startswith("'nonce-") for s in script_src) and not any(s.startswith("'sha") for s in script_src):
            recommendations.append(
                "CSP: 'script-src' contains 'unsafe-inline' without a nonce or hash, which completely bypasses protection against XSS."
            )

    if "'unsafe-eval'" in script_src:
        is_weak = True
        recommendations.append(
            "CSP: 'script-src' contains 'unsafe-eval', which allows string evaluation APIs like eval(), increasing XSS risk."
        )

    if "*" in script_src or "http:" in script_src or "https:" in script_src:
        is_weak = True
        recommendations.append(
            "CSP: 'script-src' uses a wildcard (*) or a broad scheme (http:), which is overly permissive. Specify trusted domains instead."
        )

    # --- Check for missing but important directives ---
    if "object-src" not in directives:
        recommendations.append(
            "CSP: The 'object-src' directive is missing. It's recommended to set it to 'none' to prevent plugin execution."
        )
    elif object_src and object_src != ["'none'"]:
        is_weak = True
        recommendations.append("CSP: 'object-src' is not set to 'none'. Disabling plugins via `object-src 'none'` is recommended.")

    status = "Weak" if is_weak or not recommendations else "Strong"

    return {
        "status": status,
        "value": value,
        "recommendation": " ".join(recommendations),
    }


def _evaluate_xcto(value: str) -> Dict[str, Any]:
    """Evaluates the X-Content-Type-Options header."""
    if value.lower() == "nosniff":
        return {"status": "Present", "value": value}
    return {
        "status": "Invalid",
        "value": value,
        "recommendation": "Set X-Content-Type-Options to 'nosniff'.",
    }


def _evaluate_xfo(value: str) -> Dict[str, Any]:
    """Evaluates the X-Frame-Options header."""
    val_lower = value.lower()
    if val_lower in ("deny", "sameorigin"):
        return {"status": "Present", "value": value}
    return {
        "status": "Weak",
        "value": value,
        "recommendation": "X-Frame-Options should be set to 'DENY' or 'SAMEORIGIN'.",
    }


def _evaluate_xxss(value: str) -> Dict[str, Any]:
    """Evaluates the X-XSS-Protection header."""
    if value.startswith("0"):
        return {
            "status": "Disabled",
            "value": value,
            "recommendation": (
                "X-XSS-Protection is disabled. While modern browsers have built-in " "protection, ensure CSP is properly configured."
            ),
        }
    if value.startswith("1"):
        return {
            "status": "Enabled",
            "value": value,
            "recommendation": (
                "X-XSS-Protection is enabled. Note that this header is deprecated in " "favor of a strong Content-Security-Policy."
            ),
        }
    return {"status": "Invalid", "value": value}


def _evaluate_generic(value: str) -> Dict[str, Any]:
    """Generic evaluation for headers that only need to be present."""
    return {"status": "Present", "value": value}


HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "eval_func": _evaluate_hsts,
        "severity": "High",
        "recommendation": "Implement HSTS to enforce HTTPS.",
    },
    "Content-Security-Policy": {
        "eval_func": _evaluate_csp,
        "severity": "High",
        "recommendation": ("Implement a Content-Security-Policy (CSP) to mitigate XSS and other " "injection attacks."),
    },
    "X-Frame-Options": {
        "eval_func": _evaluate_xfo,
        "severity": "Medium",
        "recommendation": ("Implement X-Frame-Options or CSP 'frame-ancestors' to prevent " "clickjacking."),
    },
    "X-Content-Type-Options": {
        "eval_func": _evaluate_xcto,
        "severity": "Medium",
        "recommendation": "Set X-Content-Type-Options to 'nosniff' to prevent MIME-sniffing.",
    },
    "Referrer-Policy": {
        "eval_func": _evaluate_generic,
        "severity": "Low",
        "recommendation": "Set a Referrer-Policy to control info leakage in the Referer header.",
    },
    "Permissions-Policy": {
        "eval_func": _evaluate_generic,
        "severity": "Low",
        "recommendation": ("Implement a Permissions-Policy (formerly Feature-Policy) to control " "browser feature access."),
    },
    "X-XSS-Protection": {
        "eval_func": _evaluate_xxss,
        "severity": "Low",
        "recommendation": "",  # Recommendations are handled in the eval function
    },
}


async def analyze_http_headers(domain: str, verify_ssl: bool = True, **kwargs) -> Dict[str, Any]:
    """
    Performs a detailed analysis of HTTP security headers.
    Args:
        domain: The domain to analyze.
        verify_ssl: Whether to verify SSL certificates. Defaults to True.
    """
    results: Dict[str, Any] = {
        "analysis": {},
        "recommendations": [],
        "final_url": None,
        "error": None,
    }
    urls_to_check = [f"https://{domain}", f"http://{domain}"]
    logger.debug(f"Analyzing HTTP headers for {domain}")

    async with httpx.AsyncClient(follow_redirects=True, verify=verify_ssl) as client:
        for url in urls_to_check:
            try:
                response = await client.get(url, timeout=10)
                response.raise_for_status()

                results["final_url"] = str(response.url)

                for header_name, check_config in HEADER_CHECKS.items():
                    header_value = response.headers.get(header_name)
                    if header_value:
                        analysis_result = check_config["eval_func"](header_value)
                        results["analysis"][header_name] = analysis_result
                        if analysis_result.get("recommendation"):
                            results["recommendations"].append(analysis_result["recommendation"])
                    else:
                        results["analysis"][header_name] = {"status": "Missing"}
                        results["recommendations"].append(check_config["recommendation"])

                # If we get a successful response, we can stop.
                results["error"] = None  # Clear any previous error from a failed HTTPS attempt
                return results

            except httpx.RequestError as e:
                error_message = f"HTTP request to {url} failed: {type(e).__name__}"
                results["error"] = error_message
                logger.debug(error_message)
            except Exception as e:
                results["error"] = f"An unexpected error occurred while checking {url}: {e}"

    return results
