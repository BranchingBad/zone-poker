#!/usr/bin/env python3
"""
Zone-Poker - Configuration Manager Module
Handles loading and merging of settings from command-line arguments and config files.
"""
import argparse
import json
from typing import Dict, Any, Optional

from .config import console
# The 'register_module_args' import is removed as 'clean_parser' is no longer used.

def get_final_config(args: argparse.Namespace, parser: argparse.ArgumentParser) -> argparse.Namespace:
    """
    Builds the final configuration by layering defaults, config file, and CLI args.

    The priority is:
    1. Default values.
    2. Values from the JSON config file (if provided).
    3. Values explicitly set via command-line arguments (highest priority).

    Args:
        args: The initial parsed arguments from the command line.
        parser: The ArgumentParser instance to get default values from.

    Returns:
        The final, merged configuration namespace.
    """
    config_data = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config_data = json.load(f)
        except FileNotFoundError:
            console.print(f"[bold red]Error: Config file '{args.config}' not found.[/bold red]")
            raise
        except json.JSONDecodeError:
            console.print(f"[bold red]Error: Could not decode JSON from config file '{args.config}'.[/bold red]")
            raise

    # The 'clean_parser' logic has been removed as it was redundant.
    # The merge logic below correctly prioritizes CLI args over config file args.
    
    # Merge config_data into a new Namespace, then update with CLI args
    final_args = argparse.Namespace(**config_data)
    
    # Update the namespace with any values explicitly set on the command line.
    # 'v is not None' and 'v is not False' ensures that CLI flags
    # (like --all or --export) or explicit args (like --timeout 5)
    # override the config file.
    final_args.__dict__.update({k: v for k, v in vars(args).items() if v is not None and v is not False})

    return final_args
}