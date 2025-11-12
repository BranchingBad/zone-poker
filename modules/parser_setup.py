import argparse
from modules.dispatch_table import register_module_args


def setup_parser() -> argparse.ArgumentParser:
    """Creates and configures the argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Zone-Poker - A professional DNS reconnaissance and OSINT tool for "
            "comprehensive domain analysis.\nCreated by BranchingBad"
        ),
        epilog="""
Examples:
  zone-poker example.com --all --export
  zone-poker example.com --mail --whois --export -O /path/to/reports/
  zone-poker example.com --records --types A,MX,TXT
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--version", action="version", version="%(prog)s 1.0.5")

    # --- Input Configuration ---
    input_group = parser.add_argument_group('Input Configuration')
    domain_or_file_group = input_group.add_mutually_exclusive_group()
    domain_or_file_group.add_argument(
        "domain", nargs='?', default=None,
        help="Target domain to analyze (e.g., example.com)"
    )
    domain_or_file_group.add_argument(
        "-f", "--file",
        help="Path to a file (JSON or YAML) containing a list of domains to analyze."
    )
    input_group.add_argument(
        "-c", "--config",
        help="Path to a JSON or YAML config file with scan options.")

    # --- Scan Control ---
    scan_group = parser.add_argument_group('Scan Control')
    scan_group.add_argument(
        "-a", "--all", action="store_true", help="Run all analysis modules.")
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Set network request timeout in seconds (default: 5).")
    scan_group.add_argument(
        "--retries",
        type=int,
        default=0,
        help="Number of times to retry a failed domain scan (default: 0).")
    scan_group.add_argument(
        "--types",
        help="Comma-separated list of DNS record types to query (e.g., 'A,MX,TXT')."
    )
    scan_group.add_argument(
        "--resolvers",
        help="Comma-separated list of custom DNS resolvers to use.")

    # --- Output Control ---
    output_group = parser.add_argument_group('Output Control')
    output_group.add_argument("-e",
                              "--export",
                              action="store_true",
                              help="Export default reports (.json, .txt).")
    output_group.add_argument(
        "-O", "--output-dir",
        help="Directory to save reports (defaults to Desktop).")
    output_group.add_argument("--filename-template",
                              default="{domain}_dnsint_{timestamp}",
                              help="Template for report filenames. "
                              "Default: '{domain}_dnsint_{timestamp}'.",
                              )
    output_group.add_argument(
        "--html-file",
        help="Export an HTML report to the specified file path."
    )
    output_group.add_argument(
        "--log-file", help="Path to a file to save detailed, verbose logs.")
    output_group.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show detailed error logs during the scan."
    )
    output_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Show minimal console output (suppresses tables and headers)."
    )
    output_group.add_argument(
        "--output",
        choices=['table', 'json', 'csv', 'xml', 'html'],
        default='table',
        help=("Console output format. 'table' for human-readable, others for "
              "machine-readable.")
    )

    # --- Analysis Modules ---
    module_group = parser.add_argument_group(
        'Analysis Modules', 'Run specific modules by adding their flags.'
    )
    # Let modules register their own command-line arguments
    register_module_args(module_group)

    return parser
