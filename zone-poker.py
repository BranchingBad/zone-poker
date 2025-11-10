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

# Import all our modules
from modules.orchestrator import run_analysis_modules, MODULE_DISPATCH_TABLE, register_module_args
from modules.export import export_reports
from modules.config_manager import get_final_config
from modules.config import console
import dns.resolver

async def main():
    parser = argparse.ArgumentParser(
        description="Zone-Poker - A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis.\nCreated by wh0xac",
        epilog="""
Examples:
  python3 zone-poker.py example.com --all --export
  python3 zone-poker.py example.com --mail --whois --export
  python3 zone-poker.py example.com --propagation --records --tech
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Group for mutually exclusive domain vs. file input
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("domain", nargs='?', default=None, help="Target domain to analyze (e.g., example.com)")
    input_group.add_argument("-f", "--file", help="Path to a JSON file containing a list of domains to analyze.")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    parser.add_argument("-c", "--config", help="Path to a JSON config file with scan options.")
    parser.add_argument("-a", "--all", action="store_true", help="Run all analysis modules")
    parser.add_argument("-e", "--export", action="store_true", help="Export JSON and TXT reports to the Desktop")
    parser.add_argument("--timeout", type=int, default=5, help="Set DNS query timeout (default 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed error logs during the scan")
    parser.add_argument("-q", "--quiet", action="store_true", help="Show minimal console output (suppress tables and headers)")
    
    # Let modules register their own command-line arguments
    register_module_args(parser)

    cli_args = parser.parse_args()
    
    try:
        # Get the final configuration, merging defaults, config file, and CLI arguments
        # --- THIS LINE IS CHANGED ---
        args = get_final_config(parser, cli_args)
    except (FileNotFoundError, json.JSONDecodeError):
        return # Error message is printed by the config manager

    domains_to_scan = []
    # The domain/file input can also come from the config file
    domain_input = getattr(args, 'domain', None)
    file_input = getattr(args, 'file', None)

    if file_input:
        try:
            with open(file_input, 'r') as f:
                domains_from_file = json.load(f)
            if not isinstance(domains_from_file, list):
                console.print(f"[bold red]Error: The JSON file '{file_input}' must contain a list of domain strings.[/bold red]")
                return
            domains_to_scan.extend(domains_from_file)
        except FileNotFoundError:
            console.print(f"[bold red]Error: The file '{file_input}' was not found.[/bold red]")
            return
        except json.JSONDecodeError:
            console.print(f"[bold red]Error: Could not decode JSON from the file '{file_input}'. Please check the format.[/bold red]")
            return
    elif domain_input:
        domains_to_scan.append(domain_input)

    if not domains_to_scan:
        console.print("[bold red]Error: No target domain specified. Provide a domain, a file with '-f', or a config file with 'domain' or 'file' key.[/bold red]")
        parser.print_help()
        return
    
    total_domains = len(domains_to_scan)
    for i, domain_name in enumerate(domains_to_scan):
        domain = domain_name.strip().rstrip('.')
        
        if total_domains > 1:
            console.print(f"\n[bold magenta]===== Scanning domain {i+1} of {total_domains}: {domain} =====[/bold magenta]")

        # Determine which modules to run.
        # If --all is specified or no specific modules are chosen, run all of them.
        modules_to_run = [
            name for name in MODULE_DISPATCH_TABLE if getattr(args, name, False) # Use final merged args
        ]
        if getattr(args, 'all', False) or not modules_to_run:
            modules_to_run = list(MODULE_DISPATCH_TABLE.keys())

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


if __name__ == '__main__':
    asyncio.run(main())