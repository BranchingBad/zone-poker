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
# Import the central configuration
from .dispatch_table import MODULE_DISPATCH_TABLE
# Import the one display function this module calls directly
from .display import display_summary, display_critical_findings


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

    # --- Centralized Resolver RE-ADDED ---
    # Use the standard SYNCHRONOUS resolver. We will call it via asyncio.to_thread.
    # By not setting any flags, we avoid sending the DNSSEC OK (DO) bit,
    # which was causing SERVFAIL errors from public resolvers when querying
    # for records on unsigned domains (like the _dmarc record).
    # --- THIS IS THE FIX ---
    # The default resolver sets `want_dnssec=True`. We must explicitly disable it.
    resolver = dns.resolver.Resolver(configure=False) # Start with a clean resolver
    resolver.want_dnssec = False # Explicitly disable DNSSEC queries
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

    # Context of all available data for analysis functions
    analysis_context = {
        "domain": domain,
        "resolver": resolver, # --- THIS IS THE FIX ---
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
            # --- THIS IS THE FIX: Pass the actual data key as the kwarg name ---
            # e.g., for a module depending on 'records', this makes the 'records'
            # kwarg available to its analysis function.
            func_kwargs[dep_key] = all_data.get(dep_key, {})

        sig = inspect.signature(analysis_func)
        for param in sig.parameters:
            # --- THIS IS THE FIX ---
            # Only add from context if not already populated by a dependency.
            if param in analysis_context and param not in func_kwargs:
                func_kwargs[param] = analysis_context[param]

        try:
            # Run async or sync analysis function
            if asyncio.iscoroutinefunction(analysis_func):
                result = await analysis_func(**func_kwargs)
            else:
                # --- THIS IS THE FIX: Run sync functions in a thread executor ---
                # This prevents synchronous, blocking calls (like DNS queries)
                # from stalling the entire asyncio event loop.
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(None, lambda: analysis_func(**func_kwargs))
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

    display_critical_findings(all_data, args.quiet)
    display_summary(all_data, args.quiet)

    if not args.quiet:
        console.print(f"✓ Scan completed for {domain}")
        console.print(f"Finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    return all_data