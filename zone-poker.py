#!/usr/bin/env python3
"""
Zone poker
A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis
"""

import argparse
import asyncio
import traceback
from datetime import datetime

# Import all our modules
from modules.orchestrator import run_analysis_modules, MODULE_DISPATCH_TABLE, register_module_args
from modules.export import export_reports
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
    
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    parser.add_argument("domain", help="Target domain to analyze (e.g., example.com)")
    parser.add_argument("-a", "--all", action="store_true", help="Run all analysis modules")
    parser.add_argument("-e", "--export", action="store_true", help="Export JSON and TXT reports to the Desktop")
    parser.add_argument("--timeout", type=int, default=5, help="Set DNS query timeout (default 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed error logs during the scan")
    parser.add_argument("-q", "--quiet", action="store_true", help="Show minimal console output (suppress tables and headers)")
    
    # Let modules register their own command-line arguments
    register_module_args(parser)

    args = parser.parse_args()
    
    domain = args.domain.strip().rstrip('.')
    
    # Determine which modules to run.
    # If --all is specified or no specific modules are chosen, run all of them.
    modules_to_run = [
        name for name in MODULE_DISPATCH_TABLE if getattr(args, name, False)
    ]
    if args.all or not modules_to_run:
        modules_to_run = list(MODULE_DISPATCH_TABLE.keys())

    try:
        # The orchestrator will handle running analysis, managing dependencies, and displaying results.
        all_data = await run_analysis_modules(modules_to_run, domain, args)
        
        if args.export:
            export_reports(domain, all_data)

    except dns.resolver.NXDOMAIN:
        console.print(f"[bold red]Error: The domain '{domain}' does not exist (NXDOMAIN).[/bold red]")
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]Scan aborted by user.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        if args.verbose:
            console.print(f"\n[dim]{traceback.format_exc()}[/dim]")
        console.print(f"Scan for {domain} terminated due to error.")


if __name__ == '__main__':
    asyncio.run(main())