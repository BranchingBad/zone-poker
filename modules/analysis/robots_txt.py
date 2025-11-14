#!/usr/bin/env python3
"""
Zone-Poker - robots.txt Analysis Module
This module checks for the presence and content of a robots.txt file.
"""

import logging
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

# A list of common sensitive paths that might be disallowed in robots.txt
# Organized by category for clarity.
SENSITIVE_PATHS = [
    # Common Admin/Login Paths
    "/admin",
    "/administrator",
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/dashboard",
    "/manage",
    "/portal",
    "/user/login",
    "/user/password",
    "/user/register",
    "/wp-admin",
    "/phpmyadmin",
    # Common API/Backend Paths
    "/api",
    "/cgi-bin",
    "/includes",
    # Version Control & Config Files
    "/.git",
    "/.svn",
    "/.hg",
    "/.env",
    "/config",
    "/backup",
    # Potentially Sensitive Directories
    "/private",
    "/secret",
    "/internal",
    "/secure",
    # Development/Staging Paths
    "/dev",
    "/staging",
    "/test",
]


async def analyze_robots_txt(domain: str, timeout: int, **kwargs) -> Dict[str, Any]:
    """
    Fetches and analyzes the robots.txt file for misconfigurations and interesting entries.
    """
    results: Dict[str, Any] = {
        "found": False,
        "url": None,
        "content_lines": [],
        "sitemaps": [],
        "disallowed_sensitive": [],
        "wildcard_disallows": [],
        "error": None,
    }
    url = f"https://{domain}/robots.txt"
    results["url"] = url

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            response = await client.get(url)
            if response.status_code == 200:
                results["found"] = True
                results["content_lines"] = response.text.splitlines()
                for line in results["content_lines"]:
                    line_lower = line.strip().lower()
                    if line_lower.startswith("sitemap:"):
                        results["sitemaps"].append(line.split(":", 1)[1].strip())
                    elif line_lower.startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path in ("/", "*"):
                            results["wildcard_disallows"].append(path)
                        if any(path.startswith(p) for p in SENSITIVE_PATHS):
                            results["disallowed_sensitive"].append(path)
    except httpx.RequestError as e:
        results["error"] = f"Request to {url} failed: {e.__class__.__name__}"
        logger.debug(f"robots.txt check for {domain} failed: {e}")

    return results
