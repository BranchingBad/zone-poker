#!/usr/bin/env python3
"""
Zone-Poker - Utilities Module
Contains helper functions used across different modules.
"""
import sys
import re
import os
from pathlib import Path

# Import the shared console object
from .config import console

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