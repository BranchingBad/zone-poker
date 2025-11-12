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
from typing import List
import logging # Import logging

# --- THESE IMPORTS ARE UPDATED ---
from modules.orchestrator import run_analysis_modules
from modules.dispatch_table import MODULE_DISPATCH_TABLE, register_module_args
from modules.parser_setup import setup_parser
# --- END UPDATED IMPORTS ---
from modules.export import handle_output
from modules.config_manager import setup_configuration_and_domains
from modules.logger_config import setup_logging
from modules.config import console
import dns.resolver
from rich.progress import Progress # Import Progress

logger = logging.getLogger(__name__) # Get logger instance

async def scan_domain(domain_name: str, args: argparse.Namespace, modules_to_run: List[str], progress: Progress = None, task_id=None) -> bool:
    """
    Orchestrates the scanning process for a single domain.
    """
    domain = domain_name.strip().rstrip('.')
    if progress and task_id is not None:
        progress.update(task_id, description=f"[cyan]Scanning {domain}...")

    try:
        # The orchestrator will handle running analysis, managing dependencies, and displaying results.
        all_data = await run_analysis_modules(modules_to_run, domain, args)

        # Handle console output (e.g., json, xml, html)
        if args.output != 'table':
            handle_output(all_data, args.output)

        # Handle file exports (txt, json)
        handle_output(all_data, 'file') # Use a dedicated identifier for file exports
        return True

    except dns.resolver.NXDOMAIN:
        logger.error(f"Error: The domain '{domain}' does not exist (NXDOMAIN).")
        console.print(f"[bold red]Error: The domain '{domain}' does not exist (NXDOMAIN).[/bold red]")
        return False
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]Scan aborted by user.[/bold yellow]")
        # This will be caught by the main_wrapper and exit gracefully.
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred while scanning '{domain}': {e}", exc_info=getattr(args, 'verbose', False))
        console.print(f"[bold red]An unexpected error occurred while scanning '{domain}': {e}[/bold red]")
        if getattr(args, 'verbose', False):
            console.print(f"\n[dim]{traceback.format_exc()}[/dim]")
        return False


async def run_all_scans(domains_to_scan: List[str], args: argparse.Namespace, modules_to_run: List[str]):
    """
    Manages the scanning of multiple domains with a retry mechanism.
    """
    domains_to_retry = list(domains_to_scan)
    successful_domains = []
    num_retries = getattr(args, 'retries', 0)
    
    with Progress(
        "[progress.description]{task.description}",
        "[progress.percentage]{task.percentage:>3.0f}%",
        console=console,
        disable=args.quiet or len(domains_to_scan) <= 1,
    ) as progress:
        main_task_id = progress.add_task("[cyan]Scanning domains...", total=len(domains_to_scan))

        for attempt in range(num_retries + 1):
            if not domains_to_retry:
                break  # All domains succeeded

            if attempt > 0:
                console.print(f"\n[bold yellow]Retrying {len(domains_to_retry)} failed domains (Attempt {attempt + 1}/{num_retries + 1})...[/bold yellow]")
                await asyncio.sleep(2)  # Wait a moment before retrying

            tasks = [scan_domain(domain, args, modules_to_run, progress, main_task_id) for domain in domains_to_retry]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            failed_this_round = []
            for i, result in enumerate(results):
                domain_name = domains_to_retry[i]
                if isinstance(result, KeyboardInterrupt):
                    raise result # Propagate immediately
                
                # A task is successful if it returned True and raised no exception
                if result is True and domain_name not in successful_domains:
                    successful_domains.append(domain_name)
                    progress.advance(main_task_id)
                elif result is False or isinstance(result, Exception):
                    failed_this_round.append(domain_name)
                    if attempt == num_retries: # Final attempt failed
                        logger.error(f"Scan for domain '{domain_name}' failed permanently after {num_retries + 1} attempts.")
                        console.print(f"[bold red]Scan for domain '{domain_name}' failed permanently.[/bold red]")

            domains_to_retry = failed_this_round


def _display_welcome_banner(args: argparse.Namespace):
    """Displays a welcome banner if not in quiet or machine-readable output mode."""
    if not args.quiet and args.output == 'table':
        banner = """
███████╗ ██████╗ ███╗   ██╗███████╗    ██████╗  ██████╗ ██╗  ██╗███████╗██████╗ 
╚══███╔╝██╔═══██╗████╗  ██║██╔════╝    ██╔══██╗██╔═══██╗╚██╗██╔╝██╔════╝██╔══██╗
  ███╔╝ ██║   ██║██╔██╗ ██║█████╗      ██████╔╝██║   ██║ ╚███╔╝ █████╗  ██████╔╝
 ███╔╝  ██║   ██║██║╚██╗██║██╔══╝      ██╔═══╝ ██║   ██║ ██╔██╗ ██╔══╝  ██╔══██╗
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
    
    # Determine which modules to run (only need to do this once)
    modules_to_run = [
        name for name in MODULE_DISPATCH_TABLE if getattr(args, name, False) # Use final merged args
    ]
    if getattr(args, 'all', False) or not modules_to_run:
        modules_to_run = list(MODULE_DISPATCH_TABLE.keys())

    await run_all_scans(domains_to_scan, args, modules_to_run)


# --- THIS IS THE NEW WRAPPER FUNCTION ---
def main_wrapper():
    """Synchronous wrapper to run the async main function."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]Scan aborted by user.[/bold yellow]")

if __name__ == '__main__':
    main_wrapper()