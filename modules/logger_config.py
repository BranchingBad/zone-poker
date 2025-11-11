#!/usr/bin/env python3
"""
Zone-Poker - Logger Configuration
Sets up the application-wide logger.
"""
import logging
import sys
from typing import Optional
import argparse

from rich.logging import RichHandler
from .config import console

def initialize_logging(cli_args: argparse.Namespace):
    """
    Initial, pre-config logging setup based on raw CLI args.
    This ensures logging is active before the config file is even read.
    """
    verbose = getattr(cli_args, 'verbose', False)
    quiet = getattr(cli_args, 'quiet', False)
    log_file = getattr(cli_args, 'log_file', None)
    setup_logging(verbose, quiet, log_file)

def setup_logging(verbose: bool, quiet: bool, log_file: Optional[str] = None):
    """
    Configures the root logger for the application.

    - Console logging level is set based on verbosity flags.
    - File logging is enabled if a log_file path is provided.

    Args:
        verbose: If True, sets console level to DEBUG.
        quiet: If True, sets console level to WARNING.
        log_file: Path to a file where logs should be saved.
    """
    # Determine the console logging level
    if quiet:
        console_level = logging.WARNING
    elif verbose:
        console_level = logging.DEBUG
    else:
        console_level = logging.INFO

    # Get the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Set the lowest level for the logger itself

    # Clear any existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create console handler using RichHandler for better formatting
    console_handler = RichHandler(
        console=console,
        level=console_level, # Set the level for the handler
        show_time=False,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        show_level=verbose # Only show [INFO], [DEBUG] etc. when verbose
    )
    logger.addHandler(console_handler)

    # Create file handler if a path is provided
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='w')
        file_handler.setLevel(logging.DEBUG) # Always log DEBUG level to file
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)