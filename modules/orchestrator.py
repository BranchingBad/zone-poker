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
    display_osint_results, display_summary, display_ptr_lookups
)

def display_zone_analysis(zone_info: Dict, quiet: bool): # This function is no longer used but kept for reference
    """Composite function to display all zone-related results."""
    pass

# The MODULE_DISPATCH_TABLE is the central configuration for the orchestrator.
# It maps a module's command-line name (e.g., "records") to its corresponding
# analysis function, display function, and dependencies.
#
# - data_key: The key used to store the module's results in the `all_data` dictionary.
# - analysis_func: The function from the `analysis` module to call.
# - display_func: The function from the `display` module to call.
# - description: A user-friendly message shown when the module starts.
# - args: A list of argument names the `analysis_func` requires. These are dynamically supplied.
# - dependencies: A list of other modules that must run before this one.
MODULE_DISPATCH_TABLE = {
    "records": {
        "data_key": "records",
        "analysis_func": get_dns_records,
        # Display is handled specially to include PTR lookups
        "display_func": lambda data, quiet: None,
        "description": "Querying DNS records..."
    },
    "zone": {
        "data_key": "zone_info", # This key will hold the combined result
        "analysis_func": attempt_axfr,
        "display_func": display_axfr_results,
        "description": "Attempting zone transfer (AXFR)...",
        "args": ["domain", "records", "timeout", "verbose"]
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
        "description": "Auditing for security misconfigurations..."
    },
    "tech": {
        "data_key": "technology",
        "analysis_func": detect_technologies,
        "display_func": display_technology_info,
        "description": "Detecting web technologies...",
    },
    "osint": {
        "data_key": "osint",
        "analysis_func": osint_enrichment,
        "display_func": display_osint_results,
        "description": "Gathering OSINT data..."
    }
}

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
        "nameserver_info": {}, "propagation": {}, "security": {}, "technology": {}, "osint": {}, "ptr_lookups": {}
    }

    # Context of all available data for analysis functions
    analysis_context = {
        "domain": domain,
        "all_data": all_data, # Allows functions to access results from other modules
        **vars(args) # Add timeout, verbose, etc.
    }

    # A set to keep track of which modules have been run to satisfy dependencies
    completed_modules = set()

    async def execute_module(module_name: str):
        """Recursively executes a module and its dependencies."""
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
        display_func = module_info["display_func"]

        # Prepare arguments for the analysis function dynamically
        # Defaults to a standard set if not specified in the dispatch table.
        required_args = module_info.get("args", ["domain", "timeout", "verbose"])
        
        # Make dependency data available in the context for the current function.
        # For example, the 'mail' module needs the results from the 'records' module.
        for dep_name in module_info.get("dependencies", []):
            dep_key = MODULE_DISPATCH_TABLE[dep_name]["data_key"]
            analysis_context[dep_key] = all_data.get(dep_key, {})

        try:
            # Build the keyword arguments dictionary for the analysis function
            func_kwargs = {arg: analysis_context[arg] for arg in required_args}
        except KeyError as e:
            console.print(f"[bold red]Error: Missing argument {e} for module '{module_name}'[/bold red]")
            return

        # Run async or sync analysis function
        if asyncio.iscoroutinefunction(analysis_func):
            result = await analysis_func(**func_kwargs)
        else:
            result = analysis_func(**func_kwargs)
        
        all_data[data_key] = result
        completed_modules.add(module_name)

        # Display results immediately after analysis
        if not args.quiet and module_name in modules_to_run and module_name != "records":
            display_func(result, args.quiet)

    # Execute all modules based on the dependency graph
    for module in modules_to_run:
        await execute_module(module)

    # Special handling for displaying DNS records and PTR lookups together
    if "records" in modules_to_run:
        all_data["ptr_lookups"] = await reverse_ptr_lookups(all_data["records"], args.timeout, args.verbose)
        display_dns_records_table(all_data["records"], args.quiet)
        display_ptr_lookups(all_data["ptr_lookups"], args.quiet)

    display_summary(all_data, args.quiet)
    if not args.quiet:
        console.print(f"✓ Scan completed for {domain}")
        console.print(f"Finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    return all_data