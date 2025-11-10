#!/usr/bin/env python3
"""
Zone-Poker - Orchestrator Module
Handles the logic for running analysis, managing data dependencies,
and displaying results.
"""
import asyncio
from datetime import datetime
from typing import Dict, Any, List

# Import shared config for the console object
from .config import console
from .analysis import (
    get_dns_records, reverse_ptr_lookups, attempt_axfr, email_security_analysis,
    whois_lookup, nameserver_analysis, propagation_check, security_audit,
    detect_technologies, osint_enrichment
)
from .display import (
    display_dns_records_table, display_ptr_table, display_axfr_results,
    display_email_security, display_whois_info, display_nameserver_analysis,
    display_propagation, display_security_audit, display_technology_info,
    display_osint_results, display_summary
)

# Map command-line arguments to their respective functions and data keys
MODULE_DISPATCH_TABLE = {
    "records": {
        "data_key": "records",
        "analysis_func": get_dns_records,
        "display_func": display_dns_records_table,
        "description": "Querying DNS records..."
    },
    "zone": {
        "data_key": "zone_info",
        "analysis_func": "run_zone_analysis", # Special case handled in orchestrator
        "display_func": "display_zone_analysis", # Special case
        "description": "Attempting zone transfer (AXFR)...",
        "dependencies": ["records"]
    },
    "mail": {
        "data_key": "email_security",
        "analysis_func": email_security_analysis,
        "display_func": display_email_security,
        "description": "Analyzing email security (SPF, DMARC)...",
        "dependencies": ["records"]
    },
    "whois": {
        "data_key": "whois",
        "analysis_func": whois_lookup,
        "display_func": display_whois_info,
        "description": "Performing WHOIS lookup..."
    },
    "nsinfo": {
        "data_key": "nameserver_info",
        "analysis_func": nameserver_analysis,
        "display_func": display_nameserver_analysis,
        "description": "Analyzing nameservers...",
        "dependencies": ["records"]
    },
    "propagation": {
        "data_key": "propagation",
        "analysis_func": propagation_check,
        "display_func": display_propagation,
        "description": "Checking DNS propagation..."
    },
    "security": {
        "data_key": "security",
        "analysis_func": security_audit,
        "display_func": display_security_audit,
        "description": "Auditing for security misconfigurations...",
        "dependencies": ["records", "zone"]
    },
    "tech": {
        "data_key": "technology",
        "analysis_func": detect_technologies,
        "display_func": display_technology_info,
        "description": "Detecting web technologies..."
    },
    "osint": {
        "data_key": "osint",
        "analysis_func": osint_enrichment,
        "display_func": display_osint_results,
        "description": "Gathering OSINT data..."
    }
}

async def run_zone_analysis(domain: str, records: Dict, timeout: int, verbose: bool) -> Dict:
    """Composite function to run all zone-related analysis."""
    axfr_data = await attempt_axfr(domain, records, timeout, verbose)
    ptr_data = await reverse_ptr_lookups(records, timeout, verbose)
    return {"axfr": axfr_data, "ptr_lookups": ptr_data}

def display_zone_analysis(zone_info: Dict, quiet: bool):
    """Composite function to display all zone-related results."""
    if quiet:
        return
    # The 'zone' module from the previous version was split into two displays
    # We call them both here to maintain the output structure.
    if "ptr_lookups" in zone_info:
        display_ptr_table(zone_info["ptr_lookups"], quiet)
    if "axfr" in zone_info:
        display_axfr_results(zone_info["axfr"], quiet)

async def run_analysis_modules(modules_to_run: List[str], domain: str, args: Any) -> Dict[str, Any]:
    """
    Orchestrates the execution of analysis modules, manages data dependencies,
    and calls the corresponding display functions.
    """
    if not args.quiet:
        console.print(f"Target: {domain}")
        console.print(f"Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    all_data = {
        "domain": domain,
        "scan_timestamp": datetime.now().isoformat(),
        # Pre-seed the data dictionary with keys for clarity
        "records": {}, "zone_info": {}, "email_security": {}, "whois": {},
        "nameserver_info": {}, "propagation": {}, "security": {}, "technology": {}, "osint": {}
    }

    # A set to keep track of which modules have been run to satisfy dependencies
    completed_modules = set()

    async def execute_module(module_name: str):
        if module_name not in MODULE_DISPATCH_TABLE or module_name in completed_modules:
            return

        module_info = MODULE_DISPATCH_TABLE[module_name]

        # Recursively execute dependencies first
        for dep in module_info.get("dependencies", []):
            await execute_module(dep)

        if not args.quiet:
            console.print(f"[cyan]» {module_info['description']}[/cyan]")

        analysis_func = module_info["analysis_func"]
        data_key = module_info["data_key"]

        # Prepare arguments for the analysis function
        func_args = [domain]
        # Dynamically add dependencies as arguments based on the dispatch table
        for dep_name in module_info.get("dependencies", []):
            dep_key = MODULE_DISPATCH_TABLE[dep_name]["data_key"]
            func_args.append(all_data.get(dep_key, {}))
        
        # Handle our special composite cases
        if analysis_func == "run_zone_analysis":
            analysis_func = run_zone_analysis
        if module_info["display_func"] == "display_zone_analysis":
            display_func = display_zone_analysis
        else:
            display_func = module_info["display_func"]

        if analysis_func == security_audit:
            func_args = [domain, all_data, args.verbose]
        else:
            func_args.extend([args.timeout, args.verbose])

        # Run async or sync analysis function
        if asyncio.iscoroutinefunction(analysis_func):
            result = await analysis_func(*func_args)
        else:
            result = analysis_func(*func_args)
        
        all_data[data_key] = result
        completed_modules.add(module_name)

        # Display results immediately after analysis
        if not args.quiet and module_name in modules_to_run:
            display_func(result, args.quiet)

    for module in modules_to_run:
        await execute_module(module)

    display_summary(all_data, args.quiet)
    if not args.quiet:
        console.print(f"✓ Scan completed for {domain}")
        console.print(f"Finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    return all_data