#!/usr/bin/env python3
"""
Zone poker
A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis
"""

import asyncio
import logging

from modules.config import console
from modules.config_manager import setup_configuration_and_domains
from modules.logger_config import setup_logging

# --- THESE IMPORTS ARE UPDATED ---
from modules.orchestrator import run_scans
from modules.parser_setup import setup_parser

logger = logging.getLogger(__name__)


def _display_welcome_banner(args):
    """Displays a welcome banner if not in quiet or machine-readable output mode."""
    if not args.quiet and args.output == "table":
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

    if args is None:  # An error occurred during config loading
        return

    # Initialize logging using the final, merged configuration
    setup_logging(args)

    # Display the welcome banner for interactive sessions
    _display_welcome_banner(args)

    if not domains_to_scan:
        error_msg = "Error: No target domain specified. Provide a domain, a file with " "'-f', or a config file."
        logger.error(error_msg)  # noqa: F541
        console.print(f"[bold red]{error_msg}[/bold red]")
        parser.print_help()
        return

    await run_scans(domains_to_scan, args)  # type: ignore


def main_wrapper():
    """Synchronous wrapper to run the async main function."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan aborted by user.[/bold yellow]")


if __name__ == "__main__":
    main_wrapper()
