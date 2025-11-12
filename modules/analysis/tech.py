#!/usr/bin/env python3
import httpx
from typing import Dict, Any
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)
# A structured dictionary for technology fingerprints
TECH_FINGERPRINTS = {
    "WordPress": {"html": ["wp-content", "wp-includes"]},
    "Joomla": {"html": ["joomla"]},
    "Drupal": {"headers": {"X-Generator": "Drupal"}, "html": ["sites/default/files"]},
    "Shopify": {"scripts": ["shopify"]},
    "React": {"scripts": ["react"]},
    "Vue.js": {"scripts": ["vue"]},
    "PHP": {"headers": {"X-Powered-By": "PHP"}},
    "ASP.NET": {"headers": {"X-Powered-By": "ASP.NET", "X-AspNet-Version": None}},
}


def _check_fingerprints(response: httpx.Response, soup: BeautifulSoup) -> set:
    """Checks response against the fingerprint dictionary."""
    detected_tech = set()
    response_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    response_text = response.text.lower()
    scripts = [
        s.get("src", "").lower() for s in soup.find_all("script") if s.get("src")
    ]

    for tech, fingerprints in TECH_FINGERPRINTS.items():
        if "headers" in fingerprints:
            for header, value in fingerprints["headers"].items():
                if header.lower() in response_headers and (
                    value is None or value.lower() in response_headers[header.lower()]
                ):
                    detected_tech.add(tech)
        if "html" in fingerprints and any(
            h in response_text for h in fingerprints["html"]
        ):
            detected_tech.add(tech)
        if "scripts" in fingerprints and any(
            s_fp in script_src
            for s_fp in fingerprints["scripts"]
            for script_src in scripts
        ):
            detected_tech.add(tech)

    return detected_tech


async def detect_technologies(
    domain: str, timeout: int, verbose: bool, **kwargs
) -> Dict[str, Any]:
    """
    Detects web technologies, CMS, and security headers using async HTTP.
    (Enhanced detection logic)
    """
    tech_data = {
        "headers": {},
        "technologies": [],
        "server": "",
        "status_code": 0,
        "error": None,
    }
    urls_to_check = [f"https://{domain}", f"http://{domain}"]
    detected_tech = set()

    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, verify=False
    ) as client:
        for url in urls_to_check:
            try:
                response = await client.get(url)
                tech_data["status_code"] = response.status_code
                tech_data["server"] = response.headers.get("Server", "")
                tech_data["headers"] = dict(response.headers)

                # Use BeautifulSoup to parse the HTML content
                soup = BeautifulSoup(response.text, "html.parser")

                # Check against the structured fingerprints
                detected_tech.update(_check_fingerprints(response, soup))

                # Generic header checks
                if powered_by := response.headers.get("X-Powered-By"):
                    detected_tech.add(powered_by)

                # Check meta generator tag
                generator_tag = soup.find("meta", attrs={"name": "generator"})
                if generator_tag and generator_tag.get("content"):
                    detected_tech.add(
                        generator_tag["content"].split(" ")[0]
                    )  # e.g., "Joomla! 1.5" -> "Joomla!"

                # If we get a successful response, we can stop.
                tech_data["error"] = None  # Clear any previous error
                tech_data["technologies"] = sorted(list(detected_tech))
                return tech_data

            except (httpx.RequestError, httpx.TooManyRedirects) as e:
                tech_data["error"] = f"Error checking {url}: {e}"
                if verbose:
                    logger.debug(f"Tech detection failed for {url}: {e}")

    tech_data["technologies"] = sorted(list(detected_tech))
    return tech_data
