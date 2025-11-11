#!/usr/bin/env python3
"""
Zone poker
A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis
"""

import argparse
import asyncio
import json
import traceback
from datetime import datetime
from typing import List

# --- THESE IMPORTS ARE UPDATED ---
from modules.orchestrator import run_analysis_modules
from modules.dispatch_table import MODULE_DISPATCH_TABLE, register_module_args
# --- END UPDATED IMPORTS ---
from modules.export import export_reports
from modules.config_manager import get_final_config
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

def get_domains_to_scan(args: argparse.Namespace, parser: argparse.ArgumentParser) -> List[str]:
    """Gets the list of domains to scan from CLI args or config file."""
    domains_to_scan = []
    domain_input = getattr(args, 'domain', None)
    file_input = getattr(args, 'file', None)

    if file_input:
        try:
            with open(file_input, 'r') as f:
                domains_from_file = json.load(f)
            if not isinstance(domains_from_file, list):
                console.print(f"[bold red]Error: The JSON file '{file_input}' must contain a list of domain strings.[/bold red]")
                return []
            domains_to_scan.extend(domains_from_file)
        except FileNotFoundError:
            console.print(f"[bold red]Error: The file '{file_input}' was not found.[/bold red]")
            return []
        except json.JSONDecodeError:
            console.print(f"[bold red]Error: Could not decode JSON from the file '{file_input}'. Please check the format.[/bold red]")
            return []
    elif domain_input:
        domains_to_scan.append(domain_input)

    if not domains_to_scan:
        console.print("[bold red]Error: No target domain specified. Provide a domain, a file with '-f', or a config file with 'domain' or 'file' key.[/bold red]")
        parser.print_help()
        return []
    
    return domains_to_scan

async def main():
    parser = setup_parser()
    cli_args = parser.parse_args()
    
    # --- THIS IS THE FIX: Initialize logging first ---
    initialize_logging(cli_args)

    try:
        # Get the final configuration, merging defaults, config file, and CLI arguments
        args = get_final_config(parser, cli_args)
    except (FileNotFoundError, json.JSONDecodeError):
        return # Error message is printed by the config manager

    domains_to_scan = get_domains_to_scan(args, parser)
    if not domains_to_scan:
        return
    
    # Determine which modules to run (only need to do this once)
    modules_to_run = [
        name for name in MODULE_DISPATCH_TABLE if getattr(args, name, False) # Use final merged args
    ]
    if getattr(args, 'all', False) or not modules_to_run:
        modules_to_run = list(MODULE_DISPATCH_TABLE.keys())
    
    # --- This is the new Progress Bar ---
    with Progress(
        "[progress.description]{task.description}",
        "[progress.percentage]{task.percentage:>3.0f}%",
        console=console,
        disable=args.quiet or len(domains_to_scan) == 1, # Don't show for one domain
    ) as progress:
        
        scan_task = progress.add_task("[cyan]Scanning domains...", total=len(domains_to_scan))

        for domain_name in domains_to_scan:
            domain = domain_name.strip().rstrip('.')
            progress.update(scan_task, description=f"[cyan]Scanning {domain}...")

            try:
                # The orchestrator will handle running analysis, managing dependencies, and displaying results.
                all_data = await run_analysis_modules(modules_to_run, domain, args)
                
                if getattr(args, 'export', False):
                    export_reports(domain, all_data)

            except dns.resolver.NXDOMAIN:
                console.print(f"[bold red]Error: The domain '{domain}' does not exist (NXDOMAIN).[/bold red]")
            except KeyboardInterrupt:
                console.print(f"\n[bold yellow]Scan aborted by user.[/bold yellow]")
                return # Exit the loop and the script
            except Exception as e:
                console.print(f"[bold red]An unexpected error occurred while scanning '{domain}': {e}[/bold red]")
                if getattr(args, 'verbose', False):
                    console.print(f"\n[dim]{traceback.format_exc()}[/dim]")
                console.print(f"Scan for {domain} terminated due to error. Moving to next domain if available.")
            
            progress.advance(scan_task)


# --- THIS IS THE NEW WRAPPER FUNCTION ---
def main_wrapper():
    """Synchronous wrapper to run the async main function."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]Scan aborted by user.[/bold yellow]")

if __name__ == '__main__':
    main_wrapper()