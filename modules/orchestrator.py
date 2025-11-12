#!/usr/bin/env python3
"""
Zone-Poker - Orchestrator Module
Handles the logic for running analysis, managing data dependencies,
and displaying results.
"""
import logging
import asyncio
import argparse
import traceback
from collections import deque
import dns.resolver
from datetime import datetime
from typing import Dict, Any, List, Set

# Import shared config for the console object
from .config import console, PUBLIC_RESOLVERS
from .export import handle_output

# Import the central configuration and display functions
from .dispatch_table import MODULE_DISPATCH_TABLE
from .display import display_summary, display_critical_findings


def _create_execution_plan(initial_modules: List[str]) -> List[str]:
    """
    Creates a complete and ordered execution plan by performing a topological sort.

    This function automatically includes all transitive dependencies for the requested
    modules and detects any circular dependencies in the graph.

    Raises:
        ValueError: If a circular dependency is detected.

    Returns:
        A list of module names in the correct order of execution.
    """
    # 1. Build the full set of modules to run, including all dependencies
    modules_to_run: Set[str] = set()
    queue = deque(initial_modules)
    while queue:
        module = queue.popleft()
        if module not in modules_to_run:
            modules_to_run.add(module)
            for dep in MODULE_DISPATCH_TABLE.get(module, {}).get("dependencies", []):
                queue.append(dep)

    # 2. Perform topological sort (Kahn's algorithm)
    in_degree = {module: 0 for module in MODULE_DISPATCH_TABLE}
    adj = {module: [] for module in MODULE_DISPATCH_TABLE}
    for module, details in MODULE_DISPATCH_TABLE.items():
        for dep in details.get("dependencies", []):
            adj[dep].append(module)
            in_degree[module] += 1

    # Initialize the queue with all nodes in our target set that have an in-degree of 0
    sort_queue = deque([m for m in modules_to_run if in_degree[m] == 0])
    sorted_order = []

    while sort_queue:
        u = sort_queue.popleft()
        sorted_order.append(u)
        for v in adj[u]:
            if v in modules_to_run:
                in_degree[v] -= 1
                if in_degree[v] == 0:
                    sort_queue.append(v)

    # 3. Check for cycles
    if len(sorted_order) != len(modules_to_run):
        raise ValueError(
            "Circular dependency detected in modules. Please check the `dependencies` in `dispatch_table.py`."
        )

    return sorted_order


async def _scan_single_domain(
    domain: str, args: argparse.Namespace, modules_to_run: List[str]
) -> Dict[str, Any]:
    """
    Orchestrates the scanning process for a single domain.
    This function runs the analysis modules and returns all collected data.
    It raises exceptions on failure, which are caught by the calling `run_scans` function.
    """
    domain = domain.strip().rstrip(".")
    if not args.quiet and args.output == "table":
        console.print(f"Target: {domain}")
        console.print(
            f"Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

    all_data = {
        "domain": domain,
        "scan_timestamp": datetime.now().isoformat(),
        "args_namespace": args,  # Added to pass args to other modules (like export)
        # Pre-seed data keys from all modules for a consistent structure
        **{details["data_key"]: {} for details in MODULE_DISPATCH_TABLE.values()},
    }

    # Create a single, shared DNS resolver for all modules.
    # We explicitly disable `want_dnssec` to prevent SERVFAIL errors from public resolvers
    # when querying unsigned domains (e.g., for _dmarc records).
    resolver = dns.resolver.Resolver(configure=False)  # Start with a clean resolver
    resolver.want_dnssec = False  # Explicitly disable DNSSEC queries
    resolver.timeout = float(args.timeout)
    resolver.lifetime = float(args.timeout)
    # Use user-provided resolvers if available, otherwise fall back to public resolvers.
    if getattr(args, "resolvers", None):
        resolver.nameservers = args.resolvers.split(",")
    else:
        resolver.nameservers = list(PUBLIC_RESOLVERS.values())

    analysis_context = {
        "domain": domain,
        "resolver": resolver,
        "all_data": all_data,  # Allows functions to access results from other modules
        "args": args,  # Added to pass full args namespace to functions
        "timeout": args.timeout,  # Explicitly pass needed args
        "verbose": args.verbose,  # Explicitly pass needed args
    }

    # Determine the correct execution order for modules based on their dependencies.
    # This avoids recursive calls and simplifies the execution flow.
    execution_plan = _create_execution_plan(modules_to_run)

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
            console.print(
                f"[bold red]Error in module '{module_name}': {type(e).__name__} - {e}[/bold red]"
            )
            if args.verbose:
                console.print_exception(show_locals=True)
            continue  # Move to the next module on error

        all_data[data_key] = result

        # Display results immediately after analysis if not in quiet mode.
        if (
            not args.quiet
            and args.output == "table"
            and (display_func := module_info.get("display_func"))
        ):
            renderable = display_func(result, quiet=False)
            if renderable:
                console.print(renderable)
                console.print()  # Add a newline for spacing

    # Display summary information if not in quiet mode and output is 'table'
    if not args.quiet and args.output == "table":
        if critical_renderable := display_critical_findings(all_data, quiet=False):
            console.print(critical_renderable)
        if summary_renderable := display_summary(all_data, quiet=False):
            console.print(summary_renderable)
        console.print(f"✓ Scan completed for {domain}")
        console.print(f"Finished at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Handle console output (e.g., json, xml, html)
    if args.output != "table":
        handle_output(all_data, args.output)

    # Handle file exports (txt, json)
    handle_output(all_data, "file")  # Use a dedicated identifier for file exports

    return all_data


async def run_scans(domains_to_scan: List[str], args: argparse.Namespace):
    """
    Manages the scanning of one or more domains with a progress bar and retry mechanism.
    """
    logger = logging.getLogger(__name__)

    # Determine which modules to run based on the final merged arguments
    modules_to_run = [
        name
        for name, details in MODULE_DISPATCH_TABLE.items()
        if (arg_name := details.get("arg_info", {}).get("name"))
        and getattr(args, arg_name, False)
    ]
    if getattr(args, "all", False) or not modules_to_run:
        modules_to_run = list(MODULE_DISPATCH_TABLE.keys())

    # If only one domain, run it directly without the progress bar and retry overhead
    if len(domains_to_scan) == 1:
        try:
            await _scan_single_domain(domains_to_scan[0], args, modules_to_run)
        except dns.resolver.NXDOMAIN:
            logger.error(
                f"Error: The domain '{domains_to_scan[0]}' does not exist (NXDOMAIN)."
            )
            console.print(
                f"[bold red]Error: The domain '{domains_to_scan[0]}' does not exist (NXDOMAIN).[/bold red]"
            )
        except Exception as e:
            logger.error(
                f"An unexpected error occurred while scanning '{domains_to_scan[0]}': {e}",
                exc_info=args.verbose,
            )
            console.print(
                f"[bold red]An unexpected error occurred while scanning '{domains_to_scan[0]}': {e}[/bold red]"
            )
            if args.verbose:
                console.print(f"\n[dim]{traceback.format_exc()}[/dim]")
        return

    # --- Logic for multiple domains with retries and progress bar ---
    from rich.progress import Progress

    domains_to_retry = list(domains_to_scan)
    successful_domains = []
    num_retries = getattr(args, "retries", 0)

    with Progress(
        "[progress.description]{task.description}",
        "[progress.percentage]{task.percentage:>3.0f}%",
        console=console,
        disable=args.quiet,
    ) as progress:
        main_task_id = progress.add_task(
            "[cyan]Scanning domains...", total=len(domains_to_scan)
        )

        for attempt in range(num_retries + 1):
            if not domains_to_retry:
                break  # All domains succeeded

            current_tasks = []
            if attempt > 0:
                console.print(
                    f"\n[bold yellow]Retrying {len(domains_to_retry)} failed domains (Attempt {attempt + 1}/{num_retries + 1})...[/bold yellow]"
                )
                await asyncio.sleep(2)

            for domain in domains_to_retry:
                task = asyncio.create_task(
                    _scan_single_domain(domain, args, modules_to_run)
                )
                current_tasks.append(task)

            results = await asyncio.gather(*current_tasks, return_exceptions=True)

            failed_this_round = []
            for i, result in enumerate(results):
                domain_name = domains_to_retry[i]
                if isinstance(result, Exception):
                    failed_this_round.append(domain_name)
                    if attempt == num_retries:  # Final attempt failed
                        logger.error(
                            f"Scan for domain '{domain_name}' failed permanently after {num_retries + 1} attempts: {result}"
                        )
                        console.print(
                            f"[bold red]Scan for domain '{domain_name}' failed permanently.[/bold red]"
                        )
                elif domain_name not in successful_domains:
                    successful_domains.append(domain_name)
                    progress.advance(main_task_id)

            domains_to_retry = failed_this_round
