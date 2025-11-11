#!/usr/bin/env python3
"""
Zone-Poker - Configuration Manager Module
Handles loading and merging of settings from command-line arguments and config files.
"""
import argparse
import json
import logging
import yaml # Import the PyYAML library
import os # Import os for path manipulation
from typing import Tuple, List, Optional, Any

logger = logging.getLogger(__name__)

from .config import console
from .utils import is_valid_domain # Import the new validation function

def load_config_file(file_path: str) -> dict:
    """Loads a configuration file, supporting JSON and YAML."""
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    with open(file_path, 'r') as f:
        if ext == '.json':
            return json.load(f)
        elif ext in ('.yaml', '.yml'):
            return yaml.safe_load(f)
        else:
            raise ValueError(f"Unsupported config file extension: {ext}. Please use .json, .yaml, or .yml.")

def setup_configuration_and_domains(parser: argparse.ArgumentParser) -> Tuple[Optional[argparse.Namespace], List[str]]:
    """
    Parses CLI args, loads config file, merges settings, and loads domains.
    This is the single source of truth for all configuration.

    The priority is:
    1. Parser defaults
    2. Values from the JSON/YAML config file (if provided, overrides defaults)
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
            config_data = load_config_file(config_file_path)
        except FileNotFoundError:
            console.print(f"[bold red]Error: Config file '{config_file_path}' not found.[/bold red]")
            return None, []
        except (json.JSONDecodeError, yaml.YAMLError, ValueError) as e:
            console.print(f"[bold red]Error: Could not decode config file '{config_file_path}'. {e}[/bold red]")
            return None, []

    # 3. Merge: Start with defaults, then layer config file
    final_config = defaults.copy()
    final_config.update(config_data)

    # 4. Layer explicit CLI args over the top
    cli_vars = vars(cli_args)
    for key, value in cli_vars.items():
        # Only override if the CLI value is different from the default
        # This prevents CLI args that are implicitly set to their defaults from overriding config file values
        if key in defaults and value != defaults[key]:
            final_config[key] = value
        # Handle boolean flags specifically: if a flag is present on CLI, it should override
        # This is a common argparse behavior where `action='store_true'` sets a default of False
        # If the flag is present, its value becomes True, which should override.
        elif key in defaults and isinstance(defaults[key], bool) and value is True:
            final_config[key] = value
        # For other cases where CLI arg is not default (e.g., domain, file path)
        elif key not in defaults:
            final_config[key] = value
    
    final_args = argparse.Namespace(**final_config)

    # 5. Load domains to scan using the final merged config
    domains_to_scan = []
    domain_input = getattr(final_args, 'domain', None)
    file_input = getattr(final_args, 'file', None)

    if file_input:
        try:
            domains_from_file = load_config_file(file_input) # Use the new loader
            if not isinstance(domains_from_file, list):
                console.print(f"[bold red]Error: The file '{file_input}' must contain a list of domain strings.[/bold red]")
                return final_args, []
            
            # Validate domains from file
            for domain in domains_from_file:
                if not is_valid_domain(domain):
                    console.print(f"[bold red]Error: Invalid domain format '{domain}' found in file '{file_input}'.[/bold red]")
                    return final_args, []
                domains_to_scan.append(domain)

        except FileNotFoundError:
            console.print(f"[bold red]Error: The file '{file_input}' was not found.[/bold red]")
            return final_args, []
        except (json.JSONDecodeError, yaml.YAMLError, ValueError) as e:
            console.print(f"[bold red]Error: Could not decode domains from the file '{file_input}'. {e}[/bold red]")
            return final_args, []
    elif domain_input:
        if not is_valid_domain(domain_input):
            console.print(f"[bold red]Error: Invalid domain format '{domain_input}'.[/bold red]")
            return final_args, []
        domains_to_scan.append(domain_input)

    return final_args, domains_to_scan