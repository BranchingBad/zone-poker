#!/usr/bin/env python3
"""
Zone-Poker - Configuration Manager Module
Handles loading and merging of settings from command-line arguments and config files.
"""
import argparse
import json
import logging
import yaml  # Import the PyYAML library
import os
from typing import Tuple, List, Optional, Any, Dict

logger = logging.getLogger(__name__)

from .config import console
from .utils import is_valid_domain  # Import the new validation function


def deep_merge_dicts(base: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merges two dictionaries. 'new' values overwrite 'base' values.
    If both values for a key are dictionaries, it merges them recursively.
    """
    merged = base.copy()
    for key, value in new.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = deep_merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config_file(file_path: str) -> dict:
    """Loads a configuration file, supporting JSON and YAML."""
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    with open(file_path, "r") as f:
        if ext == ".json":
            return json.load(f)
        elif ext in (".yaml", ".yml"):
            return yaml.safe_load(f)
        else:
            raise ValueError(
                f"Unsupported config file extension: {ext}. Please use .json, .yaml, or .yml."
            )


def setup_configuration_and_domains(
    parser: argparse.ArgumentParser,
) -> Tuple[Optional[argparse.Namespace], List[str]]:
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

    # 1. Establish base configuration: Start with parser defaults
    defaults = vars(parser.parse_args([]))
    final_config = defaults.copy()

    # 2. Layer config file settings over defaults
    config_file_path = cli_args.config
    config_data = {}  # [FIX] Initialize config_data as an empty dict
    if config_file_path:
        try:
            config_data = load_config_file(config_file_path)
        except FileNotFoundError:
            console.print(
                f"[bold red]Error: Config file '{config_file_path}' not found.[/bold red]"
            )
            return None, []
        except (json.JSONDecodeError, yaml.YAMLError, ValueError) as e:
            console.print(
                f"[bold red]Error: Could not decode config file '{config_file_path}'. {e}[/bold red]"
            )
            return None, []

    # 3. Layer explicit CLI arguments over the top (highest priority)
    cli_vars = vars(cli_args)
    cli_overrides = {}
    for key, value in cli_vars.items():
        # An argument was explicitly provided by the user if its value is not the default.
        # This correctly handles flags (like --all) and value-based args (like --timeout 10).
        if value != defaults.get(key):
            cli_overrides[key] = value

    # [FIX] Correctly merge in this order: defaults -> config_file -> cli_overrides
    config_from_file = deep_merge_dicts(final_config, config_data)
    final_config = deep_merge_dicts(config_from_file, cli_overrides)
    final_args = argparse.Namespace(**final_config)

    # 5. Load domains to scan using the final merged config
    domains_to_scan = []
    domain_input = getattr(final_args, "domain", None)
    file_input = getattr(final_args, "file", None)

    if file_input:
        try:
            domains_from_file = load_config_file(file_input)  # Use the new loader
            if not isinstance(domains_from_file, list):
                console.print(
                    f"[bold red]Error: The file '{file_input}' must contain a list of domain strings.[/bold red]"
                )
                return final_args, []

            # Validate domains from file
            for domain in domains_from_file:
                if not is_valid_domain(domain):
                    console.print(
                        f"[bold red]Error: Invalid domain format '{domain}' found in file '{file_input}'.[/bold red]"
                    )
                    return final_args, []
                domains_to_scan.append(domain)

        except FileNotFoundError:
            console.print(
                f"[bold red]Error: The file '{file_input}' was not found.[/bold red]"
            )
            return final_args, []
        except (json.JSONDecodeError, yaml.YAMLError, ValueError) as e:
            console.print(
                f"[bold red]Error: Could not decode domains from the file '{file_input}'. {e}[/bold red]"
            )
            return final_args, []
    elif domain_input:
        if not is_valid_domain(domain_input):
            console.print(
                f"[bold red]Error: Invalid domain format '{domain_input}'.[/bold red]"
            )
            return final_args, []
        domains_to_scan.append(domain_input)

    return final_args, domains_to_scan
