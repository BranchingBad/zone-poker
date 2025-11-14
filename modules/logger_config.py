#!/usr/bin/env python3
"""
Zone-Poker - Logger Configuration
Sets up the application-wide logger.
"""
import argparse
import logging

from rich.logging import RichHandler

from .config import console


def setup_logging(args: argparse.Namespace):
    """
    Configures the root logger for the application based on the final,
    merged configuration from command-line arguments and the config file.

    - Console logging level is set based on verbosity flags.
    - File logging is enabled if a log_file path is provided.

    Args:
        args: The final, merged argparse.Namespace object containing all configuration.
    """
    verbose = getattr(args, "verbose", False)
    quiet = getattr(args, "quiet", False)
    log_file = getattr(args, "log_file", None)

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
        level=console_level,
        show_time=False,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        show_level=verbose,  # Only show [INFO], [DEBUG] etc. when verbose
    )
    logger.addHandler(console_handler)

    # Create file handler if a path is provided
    if log_file:
        file_handler = logging.FileHandler(log_file, mode="w")
        # Always log DEBUG level to file
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
