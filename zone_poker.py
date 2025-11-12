#!/usr/bin/env python3
"""
Zone poker
A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis
"""

import argparse
import asyncio
import json
import traceback # Keep for verbose error logging
from datetime import datetime
from typing import List, Any
import logging # Import logging

# --- THESE IMPORTS ARE UPDATED ---
from modules.orchestrator import run_scans
from modules.parser_setup import setup_parser
# --- END UPDATED IMPORTS ---
from modules.export import handle_output
from modules.config_manager import setup_configuration_and_domains
from modules.logger_config import setup_logging
from modules.config import console
import dns.resolver
from rich.progress import Progress # Import Progress

logger = logging.getLogger(__name__) # Get logger instance

def _display_welcome_banner(args: argparse.Namespace):
    """Displays a welcome banner if not in quiet or machine-readable output mode."""
    if not args.quiet and args.output == 'table':
        banner = """
██████╗ ██████╗ ███╗   ██╗███████╗    ██████╗  ██████╗ ██╗  ██╗███████╗██████╗ 
╚══███╔╝██╔═══██╗████╗  ██║██╔════╝    ██╔══██╗██╔═══██╗╚██╗██╔╝██╔════╝██╔══██╗
  ███╔╝ ██║   ██║██╔██╗ ██║█████╗ ████ ██████╔╝██║   ██║ ╚███╔╝ █████╗  ██████╔╝
 ███╔╝  ██║   ██║██║╚██╗██║██╔══╝ ████ ██╔═══╝ ██║   ██║ ██╔██╗ ██╔══╝  ██╔══██╗
███████╗╚██████╔╝██║ ╚████║███████╗    ██║     ╚██████╔╝██╔╝ ██╗███████╗██║  ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
        """
        console.print(f"[bold cyan]{banner}[/bold cyan]")
        console.print("[bold]A professional DNS reconnaissance and OSINT tool.[/bold]\n")

async def main():
    parser = setup_parser()

    # Get the final configuration and the list of domains to scan.
    args, domains_to_scan = setup_configuration_and_domains(parser)

    if args is None: # An error occurred during config loading
        return

    # Initialize logging using the final, merged configuration
    setup_logging(args)

    # Display the welcome banner for interactive sessions
    _display_welcome_banner(args)

    if not domains_to_scan:
        logger.error("Error: No target domain specified. Provide a domain, a file with '-f', or a config file with 'domain' or 'file' key.")
        console.print("[bold red]Error: No target domain specified. Provide a domain, a file with '-f', or a config file with 'domain' or 'file' key.[/bold red]")
        parser.print_help()
        return
    
    await run_scans(domains_to_scan, args)


# --- THIS IS THE NEW WRAPPER FUNCTION ---
def main_wrapper():
    """Synchronous wrapper to run the async main function."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]Scan aborted by user.[/bold yellow]")

if __name__ == '__main__':
    main_wrapper()