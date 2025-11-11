#!/usr/bin/env python3
"""
Zone-Poker - Subdomain Takeover Detection Module
"""
import httpx
import asyncio
import logging
from typing import Dict, List, Any

# --- Example of moving display logic here ---
from rich.panel import Panel
from rich.tree import Tree
from rich import box
from ..config import console
from ..display_utils import console_display_handler
# --- End example ---

logger = logging.getLogger(__name__)

# A dictionary of fingerprints for common vulnerable services
TAKEOVER_FINGERPRINTS = {
    "Amazon S3": "The specified bucket does not exist",
    "GitHub Pages": "There isn't a GitHub Pages site here.",
    "Heroku": "No such app",
    "Shopify": "Sorry, this shop is currently unavailable.",
    "Fastly": "Fastly error: unknown domain",
    "Ghost": "The thing you were looking for is no longer here, or never was",
    "Bitbucket": "Repository not found",
    "Surge.sh": "project not found",
    "Netlify": "Not Found",
}

async def check_subdomain_takeover(records: Dict[str, List[Dict[str, Any]]], **kwargs) -> Dict[str, List[Dict[str, Any]]]:
    """
    Checks for potential subdomain takeovers via dangling CNAME records.
    """
    results: Dict[str, List[Dict]] = {"vulnerable": []}
    cname_records = records.get("CNAME", [])

    if not cname_records:
        return results

    logger.debug(f"Checking {len(cname_records)} CNAME records for takeover vulnerabilities.")

    async def check_cname(record):
        subdomain = record.get("name")
        if not subdomain:
            return

        # Check both HTTP and HTTPS
        for scheme in ["http", "https"]:
            url = f"{scheme}://{subdomain}"
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
                    response = await client.get(url, timeout=10)
                    for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                        if fingerprint in response.text:
                            results["vulnerable"].append({
                                "subdomain": subdomain,
                                "cname_target": record.get("value"),
                                "service": service,
                            })
                            return # Found a vulnerability, no need to check further
            except httpx.RequestError as e:
                logger.debug(f"Subdomain takeover check for {url} failed: {e}")

    tasks = [check_cname(rec) for rec in cname_records]
    await asyncio.gather(*tasks)
    return results

# --- DISPLAY AND EXPORT FUNCTIONS MOVED HERE ---
@console_display_handler("Subdomain Takeover")
def display_subdomain_takeover(data: dict, quiet: bool = False):
    """Displays Subdomain Takeover results in a panel."""
    vulnerable = data.get("vulnerable", [])
    
    if not vulnerable:
        panel = Panel("[green]✓ No potential subdomain takeovers found.[/green]", title="Subdomain Takeover", box=box.ROUNDED)
    else:
        tree = Tree(f"[bold red]✗ Found {len(vulnerable)} potential subdomain takeovers![/bold red]")
        for item in vulnerable:
            node = tree.add(f"[yellow]{item['subdomain']}[/yellow]")
            node.add(f"Service: [bold]{item['service']}[/bold]")
            node.add(f"CNAME Target: [dim]{item['cname_target']}[/dim]")
        panel = Panel(tree, title="Subdomain Takeover", box=box.ROUNDED, border_style="red")

    console.print(panel)

def _format_subdomain_takeover_txt(data: Dict[str, Any]) -> List[str]:
    """Formats Subdomain Takeover for the text report."""
    vulnerable = data.get("vulnerable", [])
    if not vulnerable:
        return ["No potential subdomain takeovers found."]
    report = [f"Found {len(vulnerable)} potential subdomain takeovers:"]
    for item in vulnerable:
        report.append(f"\n  - Subdomain: {item['subdomain']}")
        report.append(f"    Service: {item['service']}")
        report.append(f"    CNAME Target: {item['cname_target']}")
    return report

def export_txt_subdomain_takeover(data: Dict[str, Any]) -> str:
    """Formats Subdomain Takeover for the text report."""
    # This would use a shared helper like _create_report_section
    pass