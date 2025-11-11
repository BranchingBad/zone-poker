#!/usr/bin/env python3
"""
Zone-Poker - Orchestrator Module
Handles the logic for running analysis, managing data dependencies,
and displaying results.
"""
import asyncio
import argparse
from collections import deque
import dns.resolver # --- THIS IS THE FIX (reverted to standard resolver) ---
from datetime import datetime
from typing import Dict, Any, List, Set

# Import shared config for the console object
from .config import console, PUBLIC_RESOLVERS
# Import the central configuration and display functions
from .dispatch_table import MODULE_DISPATCH_TABLE
from .display import display_summary, display_critical_findings

def _topological_sort(modules_to_run: List[str]) -> List[str]:
    """
    Performs a topological sort on the modules to determine the correct execution order based on dependencies.
    """
    in_degree = {module: 0 for module in MODULE_DISPATCH_TABLE}
    adj = {module: [] for module in MODULE_DISPATCH_TABLE}
    
    for module, details in MODULE_DISPATCH_TABLE.items():
        for dep in details.get("dependencies", []):
            adj[dep].append(module)
            in_degree[module] += 1

    # Use a deque for an efficient queue
    queue = deque([module for module in modules_to_run if in_degree[module] == 0])
    sorted_order = []

    while queue:
        u = queue.popleft()
        sorted_order.append(u)
        for v in adj[u]:
            in_degree[v] -= 1
            if in_degree[v] == 0 and v in modules_to_run:
                queue.append(v)
    return sorted_order
async def run_analysis_modules(modules_to_run: List[str], domain: str, args: Any) -> Dict[str, Any]:
    """
    Orchestrates the execution of analysis modules, manages data dependencies,
    and calls the corresponding display functions.
    """
    if not args.quiet and args.output == 'table':
        console.print(f"Target: {domain}")
        console.print(f"Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    all_data = {
        "domain": domain,
        "scan_timestamp": datetime.now().isoformat(),
        "args_namespace": args, # Added to pass args to other modules (like export)
        # Pre-seed data keys from all modules for a consistent structure
        **{details["data_key"]: {} for details in MODULE_DISPATCH_TABLE.values()}
    }

    # Create a single, shared DNS resolver for all modules.
    # We explicitly disable `want_dnssec` to prevent SERVFAIL errors from public resolvers
    # when querying unsigned domains (e.g., for _dmarc records).
    resolver = dns.resolver.Resolver(configure=False) # Start with a clean resolver
    resolver.want_dnssec = False # Explicitly disable DNSSEC queries
    resolver.timeout = float(args.timeout)
    resolver.lifetime = float(args.timeout)
    resolver.nameservers = list(PUBLIC_RESOLVERS.values())

    analysis_context = {
        "domain": domain,
        "resolver": resolver,
        "all_data": all_data, # Allows functions to access results from other modules
        "args": args, # Added to pass full args namespace to functions
        "timeout": args.timeout, # Explicitly pass needed args
        "verbose": args.verbose, # Explicitly pass needed args
    }

    # Determine the correct execution order for modules based on their dependencies.
    # This avoids recursive calls and simplifies the execution flow.
    execution_plan = _topological_sort(modules_to_run)

    for module_name in execution_plan:
        module_info = MODULE_DISPATCH_TABLE[module_name]

        if not args.quiet:
            console.print(f"[cyan]» {module_info['description']}[/cyan]")

        analysis_func = module_info["analysis_func"]
        data_key = module_info["data_key"]

        # Build the keyword arguments for the analysis function.
        # Start with the base context.
        func_kwargs = analysis_context.copy()
        # Add the results from this module's dependencies. The keys of the results
        # (e.g., 'records_info') must match the argument names in the function signature.
        for dep_name in module_info.get("dependencies", []):
            dep_key = MODULE_DISPATCH_TABLE[dep_name]["data_key"]
            func_kwargs[dep_key] = all_data.get(dep_key, {})

        try:
            # Unify async and sync function calls.
            # `asyncio.to_thread` is used to run blocking sync functions without stalling the event loop.
            if asyncio.iscoroutinefunction(analysis_func):
                result = await analysis_func(**func_kwargs)
            else:
                # Pass the dynamically built kwargs to the function running in the thread.
                result = await asyncio.to_thread(analysis_func, **func_kwargs)
        except Exception as e:
            console.print(f"[bold red]Error in module '{module_name}': {type(e).__name__} - {e}[/bold red]")
            if args.verbose:
                console.print_exception(show_locals=True)
            continue # Move to the next module on error

        all_data[data_key] = result

        # Display results immediately after analysis if not in quiet mode.
        if not args.quiet and args.output == 'table' and (display_func := module_info.get("display_func")):
            renderable = display_func(result, quiet=False)
            if renderable:
                console.print(renderable)
                console.print() # Add a newline for spacing

    # Display summary information if not in quiet mode and output is 'table'
    if not args.quiet and args.output == 'table':
        if critical_renderable := display_critical_findings(all_data, quiet=False):
            console.print(critical_renderable)
        if summary_renderable := display_summary(all_data, quiet=False):
            console.print(summary_renderable)
        console.print(f"✓ Scan completed for {domain}")
        console.print(f"Finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    return all_data