#!/usr/bin/env python3
"""
Zone-Poker - Utilities Module
Contains helper functions used across different modules.
"""
import sys
import re
import os
from pathlib import Path
from typing import Dict, Any # Added imports for new functions
import dns.resolver # Added import

# Import the shared console object
from .config import console

# --- THIS FUNCTION IS MOVED FROM ANALYSIS.PY ---
def _get_resolver(timeout: int) -> dns.resolver.Resolver:
    """Helper function to create a robust, standard resolver."""
    resolver = dns.resolver.Resolver(configure=False)
    # resolver.set_flags(0) # <-- THIS LINE WAS THE BUG. REMOVED.
    resolver.timeout = timeout
    resolver.lifetime = timeout
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    return resolver

def get_desktop_path() -> Path:
    """
    Gets the user's desktop directory path in a cross-platform way.

    Checks for Windows, macOS, and Linux environments (including XDG standards).
    If the desktop path cannot be determined, it safely falls back to the user's home directory.

    Returns:
        A Path object representing the absolute path to the desktop or home directory.
    """
    home = Path.home()
    
    if sys.platform == "win32":
        desktop = home / "Desktop"
    elif sys.platform == "darwin": # macOS
        desktop = home / "Desktop"
    else:
        # Linux: Check for XDG user dir, then 'Desktop', then fallback to home
        desktop = Path(os.environ.get('XDG_DESKTOP_DIR', home / 'Desktop'))

    if not desktop.exists() or not desktop.is_dir():
        desktop = home # Fallback to home directory
    
    return desktop

def join_txt_chunks(chunks: list[str]) -> str:
    """Join multi-chunk TXT records (quoted strings) into a single string"""
    return "".join(chunks)

def get_parent_zone(domain: str) -> str | None:
    """Get the parent zone for a domain (for DS record lookup)"""
    parts = domain.split('.')
    # A valid domain for this purpose must have at least one dot (e.g., 'example.com')
    # and not be a TLD itself that might be in public suffix lists (e.g., 'co.uk').
    # A simple length check is a good first step.
    if len(parts) > 2 or (len(parts) == 2 and len(parts[1]) > 2): # Avoid 'co.uk' style TLDs
        return '.'.join(parts[1:])
    return None

# --- Helper Functions Moved from Analysis.py ---

def _format_rdata(rtype: str, rdata: Any, ttl: int) -> Dict[str, Any]:
    """
    Formats a single dnspython rdata object into a standardized dictionary.
    """
    record_info = {"ttl": ttl}
    if rtype == "MX":
        record_info.update({
            "value": str(rdata.exchange),
            "priority": rdata.preference,
        })
    elif rtype == "SRV":
        record_info.update({
            "value": str(rdata.target),
            "priority": rdata.priority,
            "weight": rdata.weight,
            "port": rdata.port,
        })
    # --- THIS BLOCK IS NEW ---
    elif rtype == "SOA":
        record_info.update({
            "value": str(rdata.mname),
            "rname": str(rdata.rname),
            "serial": rdata.serial,
        })
    # --- END NEW BLOCK ---
    elif rtype == "TXT":
        record_info["value"] = join_txt_chunks([t.decode('utf-8', 'ignore') for t in rdata.strings])
    else:
        record_info["value"] = str(rdata)
    return record_info

def _parse_spf_record(spf_record: str) -> Dict[str, Any]:
    """Helper to parse an SPF record string."""
    parts = spf_record.split()
    analysis = {"raw": spf_record, "mechanisms": {}}
    if parts:
        analysis["version"] = parts[0]
        for part in parts[1:]:
            if part.startswith(("redirect=", "include:", "a:", "mx:", "ip4:", "ip6:", "exists:")):
                key, _, value = part.partition(":")
                qualifier = key[0] if key[0] in "+-~?" else "+"
                key = key.lstrip("+-~?")
                analysis["mechanisms"].setdefault(key, []).append(value)
            elif part in ("-all", "~all", "+all", "?all"):
                analysis["all_policy"] = part
    return analysis