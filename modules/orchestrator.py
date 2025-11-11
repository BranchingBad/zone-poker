#!/usr/bin/env python3
"""
Zone-Poker - Orchestrator Module
Handles the logic for running analysis, managing data dependencies,
and displaying results.
"""
import asyncio
import argparse
import inspect
import dns.resolver # --- THIS IS THE FIX (reverted to standard resolver) ---
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
    display_dns_records_table, display_axfr_results, # display_ptr_table removed
    display_email_security, display_whois_info, display_nameserver_analysis,
    display_propagation, display_security_audit, display_technology_info, 
    display_osint_results, display_summary, display_ptr_lookups,
    # Import new export functions
    export_txt_records, export_txt_ptr, export_txt_zone, export_txt_mail,
    export_txt_whois, export_txt_nsinfo, export_txt_propagation,
    export_txt_security, export_txt_tech, export_txt_osint
)

# The MODULE_DISPATCH_TABLE is the central configuration for the orchestrator.
# It maps a module's command-line name (e.g., "records") to its corresponding
# analysis function, display function, and dependencies.
#
# - data_key: The key used to store the module's results in the `all_data` dictionary.
# - analysis_func: The function from the `analysis` module to call.
# - display_func: The function from the `display` module to call.
# - export_func: The function from `display` to format data for .txt reports.
# - arg_info: A dictionary defining the command-line argument for this module.
# - description: A user-friendly message shown when the module starts.
# - dependencies: A list of other modules that must run before this one.
MODULE_DISPATCH_TABLE = {
    "records": {
        "data_key": "records",
        "analysis_func": get_dns_records,
        "display_func": display_dns_records_table,
        "export_func": export_txt_records,
        "description": "Querying DNS records...",
        "arg_info": {"short": "-r", "long": "--records", "help": "Query all standard DNS record types."}
    },
    "ptr": {
        "data_key": "ptr_lookups",
        "analysis_func": reverse_ptr_lookups,
        "display_func": display_ptr_lookups,
        "export_func": export_txt_ptr,
        "description": "Performing reverse DNS (PTR) lookups...",
        "dependencies": ["records"],
        "arg_info": {"short": None, "long": "--ptr", "help": "Perform reverse DNS (PTR) lookups for A/AAAA records."}
    },
    "zone": {
        "data_key": "zone_info",
        "analysis_func": attempt_axfr,
        "display_func": display_axfr_results,
        "export_func": export_txt_zone,
        "description": "Attempting zone transfer (AXFR)...",
        "args": ["domain", "records", "timeout", "verbose"],
        "arg_info": {"short": "-z", "long": "--zone", "help": "Attempt a zone transfer (AXFR) against nameservers."}
    },
    "mail": {
        "data_key": "email_security",
        "analysis_func": email_security_analysis,
        "display_func": display_email_security,
        "export_func": export_txt_mail,
        "description": "Analyzing email security (SPF, DMARC)...",
        "dependencies": ["records"],
        "arg_info": {"short": "-m", "long": "--mail", "help": "Analyze email security records (SPF, DMARC, DKIM)."}
    },
    "whois": {
        "data_key": "whois",
        "analysis_func": whois_lookup,
        "display_func": display_whois_info,
        "export_func": export_txt_whois,
        "description": "Performing WHOIS lookup...",
        "arg_info": {"short": "-w", "long": "--whois", "help": "Perform an extended WHOIS lookup on the domain."}
    },
    "nsinfo": {
        "data_key": "nameserver_info",
        "analysis_func": nameserver_analysis,
        "display_func": display_nameserver_analysis,
        "export_func": export_txt_nsinfo,
        "description": "Analyzing nameservers...",
        "dependencies": ["records"],
        "arg_info": {"short": "-n", "long": "--nsinfo", "help": "Analyze nameserver information and check for DNSSEC."}
    },
    "propagation": {
        "data_key": "propagation",
        "analysis_func": propagation_check,
        "display_func": display_propagation,
        "export_func": export_txt_propagation,
        "description": "Checking DNS propagation...",
        "arg_info": {"short": "-p", "long": "--propagation", "help": "Check DNS propagation across public resolvers."}
    },
    "security": {
        "data_key": "security",
        "analysis_func": security_audit,
        "display_func": display_security_audit,
        "export_func": export_txt_security,
        "description": "Auditing for security misconfigurations...",
        "dependencies": ["records", "mail"], # Added dependency
        "arg_info": {"short": "-s", "long": "--security", "help": "Run a basic audit for DNS security misconfigurations."}
    },
    "tech": {
        "data_key": "technology",
        "analysis_func": detect_technologies,
        "display_func": display_technology_info,
        "export_func": export_txt_tech,
        "description": "Detecting web technologies...",
        "arg_info": {"short": "-t", "long": "--tech", "help": "Detect web technologies, CMS, and security headers."}
    },
    "osint": {
        "data_key": "osint",
        "analysis_func": osint_enrichment,
        "display_func": display_osint_results,
        "export_func": export_txt_osint,
        "description": "Gathering OSINT data...",
        "arg_info": {"short": "-o", "long": "--osint", "help": "Enrich data with passive DNS and other OSINT sources."}
    }
}

def register_module_args(parser: argparse.ArgumentParser):
    """
    Adds command-line arguments for each module to the argument parser.
    """
    for name, details in MODULE_DISPATCH_TABLE.items():
        arg_info = details.get("arg_info")
        if arg_info:
            args = [arg for arg in [arg_info.get("short"), arg_info.get("long")] if arg]
            if args:
                parser.add_argument(
                    *args,
                    dest=name,  # Ensure args.name corresponds to the module name
                    action="store_true",
                    help=arg_info.get("help", "")
                )

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
        "args_namespace": args, # Added to pass args to other modules (like export)
        # Pre-seed data keys from all modules for a consistent structure
        **{details["data_key"]: {} for details in MODULE_DISPATCH_TABLE.values()}
    }

    # --- Centralized Resolver REMOVED ---

    # Context of all available data for analysis functions
    analysis_context = {
        "domain": domain,
        # "resolver": resolver, # REMOVED
        "all_data": all_data, # Allows functions to access results from other modules
        "args": args, # Added to pass full args namespace to functions
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
        func_kwargs = {}

        # --- Handle special --types arg for 'records' module ---
        if module_name == "records":
            record_types_str = getattr(args, 'types', None)
            if record_types_str:
                func_kwargs['record_types'] = [t.strip().upper() for t in record_types_str.split(',')]
        
        # Populate dependencies
        for dep_name in module_info.get("dependencies", []):
            dep_key = MODULE_DISPATCH_TABLE[dep_name]["data_key"]
            analysis_context[dep_key] = all_data.get(dep_key, {})

        sig = inspect.signature(analysis_func)
        for param in sig.parameters:
            if param in analysis_context:
                func_kwargs[param] = analysis_context[param]

        try:
            # Run async or sync analysis function
            if asyncio.iscoroutinefunction(analysis_func):
                result = await analysis_func(**func_kwargs)
            else:
                result = analysis_func(**func_kwargs)
        except Exception as e:
            console.print(f"[bold red]Error in module '{module_name}': {type(e).__name__} - {e}[/bold red]")
            if args.verbose:
                console.print_exception(show_locals=True)
            return
        
        all_data[data_key] = result
        completed_modules.add(module_name)

        # Display results immediately after analysis
        if not args.quiet:
            display_func(result, args.quiet)

    # Execute all modules based on the dependency graph
    # We must iterate over a copy, as dependencies might add modules to run
    for module in list(modules_to_run):
        await execute_module(module)

    display_summary(all_data, args.quiet)
    if not args.quiet:
        console.print(f"✓ Scan completed for {domain}")
        console.print(f"Finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    return all_data