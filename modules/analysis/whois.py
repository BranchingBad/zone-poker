#!/usr/bin/env python3
import asyncio
import whois as whois_lib
from datetime import datetime
from typing import Dict, Any
from ..config import console

async def whois_lookup(domain: str, verbose: bool, **kwargs) -> Dict[str, Any]:
    """
    Performs an async-friendly WHOIS lookup by running the blocking
    'whois' library in a separate thread.
    """
    try:
        whois_data = await asyncio.to_thread(whois_lib.whois, domain)
        
        if whois_data and whois_data.get('domain_name'):
            cleaned_data = {}
            for k, v in whois_data.items():
                value = v
                # The python-whois library sometimes returns a list with the whois_server
                # as the second element. We only want the first, actual value.
                if isinstance(v, list) and v:
                    value = v[0]
                
                # Convert datetime objects to strings for JSON serialization
                if isinstance(value, datetime):
                    cleaned_data[k] = value.isoformat()
                else:
                    cleaned_data[k] = value
            return cleaned_data
        else:
            return {"error": "No WHOIS data returned."}
    except Exception as e:
        if verbose:
            console.print(f"[bold red]Error in whois_lookup: {e}[/bold red]")
        return {"error": str(e)}