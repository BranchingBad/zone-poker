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
from modules.export import export_reports, handle_output
from modules.config_manager import setup_configuration_and_domains
from modules.logger_config import setup_logging
from modules.config import console
import dns.resolver
from rich.progress import Progress # Import Progress

logger = logging.getLogger(__name__) # Get logger instance

async def scan_domain(domain_name: str, args: argparse.Namespace, modules_to_run: List[str], progress: Progress = None, task_id=None):
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
        export_reports(all_data)

    except dns.resolver.NXDOMAIN:
        logger.error(f"Error: The domain '{domain}' does not exist (NXDOMAIN).")
        console.print(f"[bold red]Error: The domain '{domain}' does not exist (NXDOMAIN).[/bold red]")
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]Scan aborted by user.[/bold yellow]")
        # This will be caught by the main_wrapper and exit gracefully.
        raise
    except Exception as e:
        logger.exception(f"An unexpected error occurred while scanning '{domain}': {e}")
        console.print(f"[bold red]An unexpected error occurred while scanning '{domain}': {e}[/bold red]")
        if getattr(args, 'verbose', False):
            console.print(f"\n[dim]{traceback.format_exc()}[/dim]")
        raise # Re-raise to be caught by the retry logic

async def _run_scans_with_retry(domains_to_scan: List[str], args: argparse.Namespace, modules_to_run: List[str], progress: Progress):
    """
    Manages the scanning of multiple domains with a retry mechanism.
    """
    main_task_id = progress.add_task("[cyan]Scanning domains...", total=len(domains_to_scan))
    domains_to_retry = list(domains_to_scan)
    successful_domains = []
    num_retries = getattr(args, 'retries', 0)

    for attempt in range(num_retries + 1):
        if not domains_to_retry:
            break  # All domains succeeded

        if attempt > 0:
            console.print(f"\n[bold yellow]Retrying {len(domains_to_retry)} failed domains (Attempt {attempt + 1}/{num_retries + 1})...[/bold yellow]")
            await asyncio.sleep(2)  # Wait a moment before retrying

        tasks = [
            scan_domain(domain, args, modules_to_run, progress, main_task_id)
            for domain in domains_to_retry
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        newly_failed_domains = []
        for i, result in enumerate(results):
            domain_name = domains_to_retry[i]
            if isinstance(result, Exception):
                if isinstance(result, KeyboardInterrupt):
                    raise result  # Propagate KeyboardInterrupt immediately

                newly_failed_domains.append(domain_name)
                # Only print the final error on the last attempt
                if attempt == num_retries:
                    logger.error(f"Scan for domain '{domain_name}' failed permanently: {result}")
                    console.print(f"[bold red]Scan for domain '{domain_name}' failed permanently: {result}[/bold red]")
                    if getattr(args, 'verbose', False):
                        # The traceback is already printed inside scan_domain for most errors,
                        # but this catches exceptions from the gather/asyncio layer itself.
                        logger.exception(f"Unhandled exception during bulk scan for '{domain_name}'")
                        console.print(f"[dim]{traceback.format_exc()}[/dim]")
            else:
                # On the first successful scan for this domain, add it to successes and advance the bar.
                if domain_name not in successful_domains:
                    successful_domains.append(domain_name)
                    progress.advance(main_task_id)

        # The domains to retry in the next loop are the ones that just failed.
        domains_to_retry = newly_failed_domains

    # After all retries, any domains left in domains_to_retry are the final failed ones.
    failed_domains = domains_to_retry
    return successful_domains, failed_domains


async def main():
    parser = setup_parser()

    # Get the final configuration and the list of domains to scan.
    args, domains_to_scan = setup_configuration_and_domains(parser)

    if args is None: # An error occurred during config loading
        return

    # Initialize logging using the final, merged configuration
    setup_logging(args)

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
    
    with Progress(
        "[progress.description]{task.description}",
        "[progress.percentage]{task.percentage:>3.0f}%",
        console=console,
        disable=args.quiet or len(domains_to_scan) == 1, # Don't show for one domain
    ) as progress:
        if len(domains_to_scan) > 1:
            # Use the new helper function for multi-domain scanning
            _, _ = await _run_scans_with_retry(domains_to_scan, args, modules_to_run, progress)
        elif domains_to_scan:
            # If only one domain, run it without the progress bar overhead
            await scan_domain(domains_to_scan[0], args, modules_to_run)


# --- THIS IS THE NEW WRAPPER FUNCTION ---
def main_wrapper():
    """Synchronous wrapper to run the async main function."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]Scan aborted by user.[/bold yellow]")

if __name__ == '__main__':
    main_wrapper()