#!/usr/bin/env python3
"""
Zone-Poker - Technology Detection Module
"""
from typing import Dict, Any, Set

import httpx
from bs4 import BeautifulSoup

from modules.config import console


async def detect_technologies(
    domain: str,
    timeout: int,
    verbose: bool,
    **kwargs: Any
) -> Dict[str, Any]:
    """
    Detects web technologies, CMS, and server software using async HTTP requests.
    """
    tech_data: Dict[str, Any] = {
        "server": "",
        "technologies": [],
        "status_code": 0,
        "error": None
    }
    urls_to_check = [f"https://{domain}", f"http://{domain}"]

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False  # Ignore SSL errors for broader checking
    ) as client:
        for url in urls_to_check:
            try:
                response = await client.get(url)
                tech_data["status_code"] = response.status_code
                tech_data["server"] = response.headers.get("Server", "N/A")

                detected_tech: Set[str] = set()

                # Check headers
                if "X-Powered-By" in response.headers:
                    detected_tech.add(response.headers["X-Powered-By"])
                if "X-Generator" in response.headers:
                    detected_tech.add(response.headers["X-Generator"])

                # Parse HTML for clues
                soup = BeautifulSoup(response.text, "html.parser")

                # Generator meta tag
                if gen_tag := soup.find("meta", attrs={"name": "generator"}):
                    if content := gen_tag.get("content"):
                        detected_tech.add(content)

                # Check for common framework/CMS footprints
                body_text = response.text.lower()
                if "wp-content" in body_text or "wp-json" in body_text:
                    detected_tech.add("WordPress")
                if "sites/default/files" in body_text or "drupal" in body_text:
                    detected_tech.add("Drupal")
                if "cdn.shopify.com" in body_text:
                    detected_tech.add("Shopify")
                if "joomla" in body_text:
                    detected_tech.add("Joomla")
                if "react" in body_text:
                    detected_tech.add("React")

                tech_data["technologies"] = sorted(list(detected_tech))

                # If we get a successful response, we can stop.
                return tech_data

            except (httpx.RequestError, httpx.TooManyRedirects) as e:
                tech_data["error"] = f"Failed to connect to {url}: {e}"
                if verbose:
                    console.log(f"Tech detection failed for {url}: {e}")
            except Exception as e:
                tech_data["error"] = f"An unexpected error occurred for {url}: {e}"

    return tech_data