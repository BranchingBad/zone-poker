#!/usr/bin/env python3
"""
Zone-Poker - Configuration Manager Module
Handles loading and merging of settings from command-line arguments and config files.
"""
import argparse
import json
import logging
from typing import Dict, Any, Optional

from .config import console

def get_final_config(parser: argparse.ArgumentParser, cli_args: argparse.Namespace) -> argparse.Namespace:
    """
    Builds the final configuration by layering defaults, config file, and CLI args.

    The priority is:
    1. Parser defaults
    2. Values from the JSON config file (if provided, overrides defaults)
    3. Values explicitly set via command-line arguments (highest priority, overrides all)

    Args:
        parser: The ArgumentParser object used to define defaults.
        cli_args: The initial parsed arguments from the command line.

    Returns:
        The final, merged configuration namespace.
    """
    
    # 1. Get defaults from the parser by parsing an empty list
    defaults = vars(parser.parse_args([]))
    
    # 2. Load config file data
    config_data = {}
    if cli_args.config:
        try:
            with open(cli_args.config, 'r') as f:
                config_data = json.load(f)
        except FileNotFoundError:
            logging.error(f"Config file '{cli_args.config}' not found.")
            raise
        except json.JSONDecodeError:
            logging.error(f"Could not decode JSON from config file '{cli_args.config}'.")
            raise

    # 3. Merge: Start with defaults, then layer config file
    final_config = defaults
    final_config.update(config_data)
    
    # 4. Layer explicit CLI args over the top
    # An arg is "explicit" if it's different from the parser's default value
    cli_vars = vars(cli_args)
    for key, value in cli_vars.items():
        if value != defaults.get(key):
            final_config[key] = value

    # 5. Ensure the config file path itself is correctly set, as it might
    # have been overwritten by the config file's own 'config: null'
    final_config['config'] = cli_args.config

    return argparse.Namespace(**final_config)
}