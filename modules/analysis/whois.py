#!/usr/bin/env python3
import asyncio
import whois as whois_lib
from datetime import datetime
from typing import Dict, Any
from ..config import console

async def whois_lookup(domain: str, verbose: bool) -> Dict[str, Any]:
    """
    Performs an async-friendly WHOIS lookup by running the blocking
    'whois' library in a separate thread.
    """
    try:
        whois_data = await asyncio.to_thread(whois_lib.whois, domain)
        
        if whois_data and whois_data.get('domain_name'):
            # Convert datetime objects to strings for JSON serialization
            return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in whois_data.items()}
        else:
            return {"error": "No WHOIS data returned."}
    except Exception as e:
        if verbose:
            console.print(f"[bold red]Error in whois_lookup: {e}[/bold red]")
        return {"error": str(e)}