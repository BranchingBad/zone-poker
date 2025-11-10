#!/usr/bin/env python3
"""
Zone poker
A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis
"""

import argparse
import asyncio
from datetime import datetime

# Import all our modules
from modules.orchestrator import run_analysis_modules, MODULE_DISPATCH_TABLE
from modules.export import export_reports

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
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-a", "--all", action="store_true", help="Run full DNS + OSINT + Technology scan")
    parser.add_argument("-r", "--records", action="store_true", help="Query DNS records & perform reverse PTR lookups")
    parser.add_argument("-z", "--zone", action="store_true", help="Attempt a zone transfer (AXFR) against nameservers")
    parser.add_argument("-m", "--mail", action="store_true", help="Analyze SPF, DKIM, DMARC")
    parser.add_argument("-w", "--whois", action="store_true", help="Perform extended WHOIS lookup")
    parser.add_argument("-n", "--nsinfo", action="store_true", help="Analyze nameserver info & DNSSEC")
    parser.add_argument("-p", "--propagation", action="store_true", help="Check global DNS propagation")
    parser.add_argument("-s", "--security", action="store_true", help="Run DNS misconfiguration checks")
    parser.add_argument("-o", "--osint", action="store_true", help="Enrich with passive DNS & CT data")
    parser.add_argument("-t", "--tech", action="store_true", help="Detect web technologies, CMS, servers, and security headers")
    parser.add_argument("-e", "--export", action="store_true", help="Export JSON + TXT reports to Desktop")
    parser.add_argument("--timeout", type=int, default=5, help="Set DNS query timeout (default 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed logs")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal console output")
    
    args = parser.parse_args()
    
    domain = args.domain.strip().rstrip('.')
    
    # Determine which modules to run. If no specific modules are selected, run all.
    selected_modules = [
        name for name, details in MODULE_DISPATCH_TABLE.items() 
        if getattr(args, name, False)
    ]
    
    run_all = args.all or not selected_modules

    modules_to_run = list(MODULE_DISPATCH_TABLE.keys()) if run_all else selected_modules

    try:
        # The orchestrator will handle running analysis, managing dependencies, and displaying results.
        all_data = await run_analysis_modules(modules_to_run, domain, args)
        
        if args.export:
            export_reports(domain, all_data)

    except Exception as e:
        from modules.config import console
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        if args.verbose:
            import traceback
            console.print(f"{traceback.format_exc()}")
        console.print(f"Scan for {domain} terminated due to error.")


if __name__ == '__main__':
    asyncio.run(main())