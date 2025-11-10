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

def get_final_config(args: argparse.Namespace) -> argparse.Namespace:
    """
    Builds the final configuration by layering defaults, config file, and CLI args.

    The priority is:
    1. Values from the JSON config file (if provided).
    2. Values explicitly set via command-line arguments (highest priority).

    Args:
        args: The initial parsed arguments from the command line.

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
    
    # 1. Start with the config file data
    final_args = argparse.Namespace(**config_data)
    
    # 2. Update/overwrite with any args explicitly passed on the CLI
    # This logic correctly prioritizes CLI args over config file args.
    final_args.__dict__.update({k: v for k, v in vars(args).items() if v is not None and v is not False})

    return final_args
}