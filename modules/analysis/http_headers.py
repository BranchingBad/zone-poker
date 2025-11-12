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
    directives = {part.strip().lower() for part in value.split(";")}
    has_subdomains = "includesubdomains" in directives
    has_preload = "preload" in directives
    recommendations = []

    try:
        max_age_str = next(
            (part for part in value.split(";") if "max-age" in part), None
        )
        max_age = int(max_age_str.split("=")[1].strip()) if max_age_str else 0

        if max_age < 31536000:  # 1 year
            recommendations.append(
                "HSTS 'max-age' is less than one year. Consider setting it to 31536000."
            )
        if not has_subdomains:
            recommendations.append("HSTS is missing the 'includeSubDomains' directive.")
        if not has_preload and has_subdomains and max_age >= 31536000:
            recommendations.append(
                "Consider adding the 'preload' directive to HSTS for maximum protection."
            )

        status = "Strong" if max_age >= 31536000 and has_subdomains else "Weak"
        return {
            "status": status,
            "value": value,
            "recommendation": " ".join(recommendations),
        }
    except (ValueError, IndexError):
        return {
            "status": "Invalid",
            "value": value,
            "recommendation": "HSTS 'max-age' is malformed.",
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
                "X-XSS-Protection is disabled. While modern browsers have built-in "
                "protection, ensure CSP is properly configured."
            ),
        }
    if value.startswith("1"):
        return {
            "status": "Enabled",
            "value": value,
            "recommendation": (
                "X-XSS-Protection is enabled. Note that this header is deprecated in "
                "favor of a strong Content-Security-Policy."
            ),
        }
    return {"status": "Invalid", "value": value}


def _evaluate_generic(value: str) -> Dict[str, Any]:
    """Generic evaluation for headers that only need to be present."""
    return {"status": "Present", "value": value}


HEADER_CHECKS = {
    "Strict-Transport-Security": {
        "eval_func": _evaluate_hsts,
        "recommendation": "Implement HSTS to enforce HTTPS.",
    },
    "Content-Security-Policy": {
        "eval_func": _evaluate_generic,
        "recommendation": (
            "Implement a Content-Security-Policy (CSP) to mitigate XSS and other "
            "injection attacks."
        ),
    },
    "X-Frame-Options": {
        "eval_func": _evaluate_xfo,
        "recommendation": (
            "Implement X-Frame-Options or CSP 'frame-ancestors' to prevent "
            "clickjacking."
        ),
    },
    "X-Content-Type-Options": {
        "eval_func": _evaluate_xcto,
        "recommendation": "Set X-Content-Type-Options to 'nosniff' to prevent MIME-sniffing.",
    },
    "Referrer-Policy": {
        "eval_func": _evaluate_generic,
        "recommendation": "Set a Referrer-Policy to control info leakage in the Referer header.",
    },
    "Permissions-Policy": {
        "eval_func": _evaluate_generic,
        "recommendation": (
            "Implement a Permissions-Policy (formerly Feature-Policy) to control "
            "browser feature access."
        ),
    },
    "X-XSS-Protection": {
        "eval_func": _evaluate_xxss,
        "recommendation": "",  # Recommendations are handled in the eval function
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
        "error": None,
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
                        if analysis_result.get("recommendation"):
                            results["recommendations"].append(
                                analysis_result["recommendation"]
                            )
                    else:
                        results["analysis"][header_name] = {"status": "Missing"}
                        results["recommendations"].append(
                            check_config["recommendation"]
                        )

                # If we get a successful response, we can stop.
                results["error"] = (
                    None  # Clear any previous error from a failed HTTPS attempt
                )
                return results

            except httpx.RequestError as e:
                error_message = f"HTTP request to {url} failed: {type(e).__name__}"
                results["error"] = error_message
                logger.debug(error_message)
            except Exception as e:
                results["error"] = (
                    f"An unexpected error occurred while checking {url}: {e}"
                )

    return results
