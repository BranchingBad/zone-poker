#!/usr/bin/env python3
import sys
import re
import os
from pathlib import Path

# Import the shared console object
from .config import console

def get_desktop_path() -> Path:
    """Get the desktop directory path cross-platform (Windows/Mac/Linux)"""
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

def join_txt_chunks(txt_value: str) -> str:
    """Join multi-chunk TXT records (quoted strings) into a single string"""
    parts = re.findall(r'"([^"]*)"', txt_value)
    if parts:
        return ''.join(parts)
    return txt_value.strip('"')

def get_parent_zone(domain: str) -> str | None:
    """Get the parent zone for a domain (for DS record lookup)"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[1:])
    return None