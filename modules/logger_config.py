#!/usr/bin/env python3
"""
Zone-Poker - Logger Configuration
Sets up the application-wide logger.
"""
import logging
import sys
from typing import Optional

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

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_formatter = logging.Formatter('%(message)s') # Simple format for console
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Create file handler if a path is provided
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='w')
        file_handler.setLevel(logging.DEBUG) # Always log DEBUG level to file
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)