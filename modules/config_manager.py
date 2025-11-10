#!/usr/bin/env python3
"""
Zone-Poker - Configuration Manager Module
Handles loading and merging of settings from command-line arguments and config files.
"""
import argparse
import json
from typing import Dict, Any, Optional

from .config import console
from .orchestrator import register_module_args

def get_final_config(args: argparse.Namespace) -> argparse.Namespace:
    """
    Builds the final configuration by layering defaults, config file, and CLI args.

    The priority is:
    1. Default values.
    2. Values from the JSON config file (if provided).
    3. Values explicitly set via command-line arguments (highest priority).

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

    # Create a clean parser to determine which args were defaults vs. user-supplied
    # This is a bit of a workaround to see what was explicitly set on the CLI.
    clean_parser = argparse.ArgumentParser()
    register_module_args(clean_parser) # Register module-specific args
    # Add other args that can be in config
    clean_parser.add_argument("-e", "--export", action="store_true")
    clean_parser.add_argument("--timeout", type=int)
    clean_parser.add_argument("-v", "--verbose", action="store_true")
    clean_parser.add_argument("-q", "--quiet", action="store_true")
    
    # Merge config_data into a new Namespace, then update with CLI args
    final_args = argparse.Namespace(**config_data)
    final_args.__dict__.update({k: v for k, v in vars(args).items() if v is not None and v is not False})

    return final_args