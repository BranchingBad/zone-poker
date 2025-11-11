#!/usr/bin/env python3
"""
Zone-Poker - Configuration Manager Module
Handles loading and merging of settings from command-line arguments and config files.
"""
import argparse
import json
import logging
from typing import Tuple, List, Optional, Any

logger = logging.getLogger(__name__)

from .config import console

def setup_configuration_and_domains(parser: argparse.ArgumentParser) -> Tuple[Optional[argparse.Namespace], List[str]]:
    """
    Parses CLI args, loads config file, merges settings, and loads domains.
    This is the single source of truth for all configuration.

    The priority is:
    1. Parser defaults
    2. Values from the JSON config file (if provided, overrides defaults)
    3. Values explicitly set via command-line arguments (highest priority, overrides all)

    Args:
        parser: The ArgumentParser object.

    Returns:
        A tuple containing:
        - The final, merged configuration as a namespace (or None on error).
        - A list of domains to scan.
    """
    cli_args = parser.parse_args()

    # 1. Get defaults from the parser by parsing an empty list
    defaults = vars(parser.parse_args([]))

    # 2. Load config file data
    config_data = {}
    config_file_path = cli_args.config
    if config_file_path:
        try:
            with open(config_file_path, 'r') as f:
                config_data = json.load(f)
        except FileNotFoundError:
            console.print(f"[bold red]Error: Config file '{config_file_path}' not found.[/bold red]")
            return None, []
        except json.JSONDecodeError:
            console.print(f"[bold red]Error: Could not decode JSON from config file '{config_file_path}'.[/bold red]")
            return None, []

    # 3. Merge: Start with defaults, then layer config file
    final_config = defaults.copy()
    final_config.update(config_data)

    # 4. Layer explicit CLI args over the top
    cli_vars = vars(cli_args)
    for key, value in cli_vars.items():
        if value != defaults.get(key):
            final_config[key] = value
    
    final_args = argparse.Namespace(**final_config)

    # 5. Load domains to scan using the final merged config
    domains_to_scan = []
    domain_input = getattr(final_args, 'domain', None)
    file_input = getattr(final_args, 'file', None)

    if file_input:
        try:
            with open(file_input, 'r') as f:
                domains_from_file = json.load(f)
            if not isinstance(domains_from_file, list):
                console.print(f"[bold red]Error: The JSON file '{file_input}' must contain a list of domain strings.[/bold red]")
                return final_args, []
            domains_to_scan.extend(domains_from_file)
        except FileNotFoundError:
            console.print(f"[bold red]Error: The file '{file_input}' was not found.[/bold red]")
            return final_args, []
        except json.JSONDecodeError:
            console.print(f"[bold red]Error: Could not decode JSON from the file '{file_input}'. Please check the format.[/bold red]")
            return final_args, []
    elif domain_input:
        domains_to_scan.append(domain_input)

    return final_args, domains_to_scan