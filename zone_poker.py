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

# --- THESE IMPORTS ARE UPDATED ---
from modules.orchestrator import run_analysis_modules
from modules.dispatch_table import MODULE_DISPATCH_TABLE, register_module_args
# --- END UPDATED IMPORTS ---
from modules.export import export_reports # --- THIS IS THE FIX: Renamed import
from modules.config_manager import setup_configuration_and_domains
from modules.logger_config import initialize_logging
from modules.config import console
import dns.resolver
from rich.progress import Progress # Import Progress

def setup_parser() -> argparse.ArgumentParser:
    """Creates and configures the argument parser."""
    parser = argparse.ArgumentParser(
        description="Zone-Poker - A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis.\nCreated by BranchingBad",
        epilog="""
Examples:
  zone-poker example.com --all --export
  zone-poker example.com --mail --whois --export -O /path/to/reports/
  zone-poker example.com --records --types A,MX,TXT
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Group for mutually exclusive domain vs. file input
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("domain", nargs='?', default=None, help="Target domain to analyze (e.g., example.com)")
    input_group.add_argument("-f", "--file", help="Path to a JSON file containing a list of domains to analyze.")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    
    # Core Scan Options
    parser.add_argument("-c", "--config", help="Path to a JSON config file with scan options.")
    parser.add_argument("-a", "--all", action="store_true", help="Run all analysis modules")
    parser.add_argument("--timeout", type=int, default=5, help="Set DNS query timeout (default 5)")
    parser.add_argument("--retries", type=int, default=0, help="Number of times to retry a failed domain scan (default: 0)")
    
    # Output Options
    parser.add_argument("-e", "--export", action="store_true", help="Export JSON and TXT reports")
    parser.add_argument("-O", "--output-dir", help="Path to a directory for saving reports (default: Desktop)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed error logs during the scan")
    parser.add_argument("-q", "--quiet", action="store_true", help="Show minimal console output (suppress tables and headers)")

    # Module-specific Options
    parser.add_argument("--types", help="Comma-separated list of DNS record types to query (e.g., A,MX,TXT)")
    
    # Let modules register their own command-line arguments
    register_module_args(parser)
    return parser

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
        
        if getattr(args, 'export', False):
            export_reports(domain, all_data)

    except dns.resolver.NXDOMAIN:
        console.print(f"[bold red]Error: The domain '{domain}' does not exist (NXDOMAIN).[/bold red]")
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]Scan aborted by user.[/bold yellow]")
        # This will be caught by the main_wrapper and exit gracefully.
        raise
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred while scanning '{domain}': {e}[/bold red]")
        if getattr(args, 'verbose', False):
            console.print(f"\n[dim]{traceback.format_exc()}[/dim]")

async def main():
    parser = setup_parser()
    # Initialize logging based on raw CLI args before full config merge
    initialize_logging(parser.parse_known_args()[0])

    # Get the final configuration and the list of domains to scan.
    args, domains_to_scan = setup_configuration_and_domains(parser)

    if args is None: # An error occurred during config loading
        return

    if not domains_to_scan:
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
            main_task_id = progress.add_task("[cyan]Scanning domains...", total=len(domains_to_scan))
            domains_to_retry = list(domains_to_scan)
            num_retries = getattr(args, 'retries', 0)

            for attempt in range(num_retries + 1):
                if not domains_to_retry:
                    break # All domains succeeded

                if attempt > 0:
                    console.print(f"\n[bold yellow]Retrying {len(domains_to_retry)} failed domains (Attempt {attempt}/{num_retries})...[/bold yellow]")
                    await asyncio.sleep(2) # Wait a moment before retrying

                tasks = [
                    scan_domain(domain, args, modules_to_run, progress, main_task_id)
                    for domain in domains_to_retry
                ]

                results = await asyncio.gather(*tasks, return_exceptions=True)

                currently_failed_domains = []
                for i, result in enumerate(results):
                    domain_name = domains_to_retry[i]
                    if isinstance(result, Exception):
                        if not isinstance(result, KeyboardInterrupt):
                            currently_failed_domains.append(domain_name)
                            # Only print the final error on the last attempt
                            if attempt == num_retries:
                                console.print(f"[bold red]Scan for domain '{domain_name}' failed permanently: {result}[/bold red]")
                                if getattr(args, 'verbose', False):
                                    # The traceback is already printed inside scan_domain for most errors,
                                    # but this catches exceptions from the gather/asyncio layer itself.
                                    console.print(f"[dim]{traceback.format_exc()}[/dim]")
                        else:
                            # Propagate KeyboardInterrupt
                            raise result
                    else:
                        # On the first successful scan for this domain, advance the progress bar.
                        if domain_name not in domains_to_scan or domain_name in domains_to_retry:
                             progress.advance(main_task_id)
                
                domains_to_retry = currently_failed_domains
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