#!/usr/bin/env python3
import asyncio
import whois as whois_lib
from whois.exceptions import WhoisError
from datetime import datetime
from typing import Dict, Any, List, Union
from ..config import console

def _normalize_whois_value(value: Union[str, list, datetime]) -> str:
    """
    Normalizes values from the whois library.
    - Converts lists to the first element.
    - Converts datetimes to ISO format strings.
    - Returns other types as strings.
    """
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)

async def whois_lookup(domain: str, verbose: bool, **kwargs) -> Dict[str, Any]:
    """
    Performs an async-friendly WHOIS lookup by running the blocking
    'whois' library in a separate thread.
    """
    try:
        # Run the blocking whois query in a thread to avoid stalling asyncio
        whois_data = await asyncio.to_thread(whois_lib.whois, domain)
        
        # A more reliable check for a failed lookup is to see if the raw text is empty.
        if not whois_data or not whois_data.text:
            return {"error": "No WHOIS data returned from server."}

        # Normalize all values to be JSON-serializable and consistent
        cleaned_data = {
            k: _normalize_whois_value(v)
            for k, v in whois_data.items()
            if v is not None
        }
        return cleaned_data

    except WhoisError as e:
        # This specific error often means the domain doesn't exist or has no WHOIS record.
        return {"error": f"WHOIS lookup failed: {e}"}
    except Exception as e:
        if verbose:
            console.print(f"[bold red]Error in whois_lookup: {e}[/bold red]")
        return {"error": f"An unexpected error occurred: {str(e)}"}