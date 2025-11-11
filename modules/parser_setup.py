import argparse
from modules.dispatch_table import register_module_args

def setup_parser() -> argparse.ArgumentParser:
    """Creates and configures the argument parser."""
    parser = argparse.ArgumentParser(
        description="Zone-Poker - A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis.\nCreated by BranchingBad",
        epilog="""
Examples:
  zone-poker example.com --all --export
  zone-poker example.com --mail --whois --export -O /path/to/reports/
  zone-poker example.com --records --types A,MX,TXT
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Group for mutually exclusive domain vs. file input
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("domain", nargs='?', default=None, help="Target domain to analyze (e.g., example.com)")
    input_group.add_argument("-f", "--file", help="Path to a JSON file containing a list of domains to analyze.")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    
    # Core Scan Options
    parser.add_argument("-c", "--config", help="Path to a JSON config file with scan options.")
    parser.add_argument("-a", "--all", action="store_true", help="Run all analysis modules")
    parser.add_argument("--timeout", type=int, default=5, help="Set DNS query timeout (default 5)")
    parser.add_argument("--retries", type=int, default=0, help="Number of times to retry a failed domain scan (default: 0)")
    
    # Output Options
    parser.add_argument("-e", "--export", action="store_true", help="Export JSON and TXT reports")
    parser.add_argument("-O", "--output-dir", help="Path to a directory for saving reports (default: Desktop)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed error logs during the scan")
    parser.add_argument("-q", "--quiet", action="store_true", help="Show minimal console output (suppress tables and headers)")
    parser.add_argument("--output", choices=['table', 'json', 'csv'], default='table', help="Specify output format (default: table)")
    parser.add_argument("--json-output", help="Path to save JSON output file.")
    parser.add_argument("--csv-output", help="Path to save CSV output file.")

    # Module-specific Options
    parser.add_argument("--types", help="Comma-separated list of DNS record types to query (e.g., A,MX,TXT)")
    
    # Let modules register their own command-line arguments
    register_module_args(parser)
    return parser
