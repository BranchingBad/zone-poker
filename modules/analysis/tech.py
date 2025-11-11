#!/usr/bin/env python3
import asyncio
import httpx
from typing import Dict, Any
from bs4 import BeautifulSoup
from ..config import console

async def detect_technologies(domain: str, timeout: int, verbose: bool) -> Dict[str, Any]:
    """
    Detects web technologies, CMS, and security headers using async HTTP.
    (Enhanced detection logic)
    """
    tech_data = {"headers": {}, "technologies": [], "server": "", "status_code": 0, "error": None}
    urls_to_check = [f"https://{domain}", f"http://{domain}"]
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for url in urls_to_check:
            try:
                response = await client.get(url)
                tech_data["status_code"] = response.status_code
                tech_data["server"] = response.headers.get("Server", "")
                
                headers = dict(response.headers)
                tech_data["headers"] = headers
                if headers.get("X-Powered-By"):
                    tech_data["technologies"].append(headers["X-Powered-By"])
                if headers.get("X-Generator"):
                    tech_data["technologies"].append(headers["X-Generator"])
                if "Drupal" in headers.get("X-Generator", ""):
                    tech_data["technologies"].append("Drupal")

                soup = BeautifulSoup(response.text, "html.parser")
                
                generator_tag = soup.find("meta", attrs={"name": "generator"})
                if generator_tag and generator_tag.get("content"):
                    tech_data["technologies"].append(generator_tag["content"])

                scripts = [s.get("src", "") for s in soup.find_all("script") if s.get("src")]
                if any("react" in s for s in scripts):
                    tech_data["technologies"].append("React")
                if any("vue" in s for s in scripts):
                    tech_data["technologies"].append("Vue.js")
                if any("shopify" in s for s in scripts):
                     tech_data["technologies"].append("Shopify")
                
                if "wp-content" in response.text:
                    tech_data["technologies"].append("WordPress")
                if "joomla" in response.text:
                    tech_data["technologies"].append("Joomla")

                tech_data["technologies"] = list(set(tech_data["technologies"]))
                
                return tech_data
            except (httpx.RequestError, httpx.TooManyRedirects) as e:
                tech_data["error"] = f"Error checking {url}: {e}"
                if verbose:
                    console.print(f"[dim]Tech detection failed for {url}: {e}[/dim]")
            except Exception as e:
                tech_data["error"] = f"Unexpected error checking {url}: {e}"
                if verbose:
                    console.print(f"[dim]Tech detection failed for {url}: {e}")
    
    return tech_data