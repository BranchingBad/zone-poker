# Zone-Poker

A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis.

## Description

Zone-Poker is a powerful and flexible tool designed for security professionals, system administrators, and researchers to perform in-depth DNS enumeration and gather open-source intelligence (OSINT) on a given domain. It consolidates multiple scanning techniques into a single, easy-to-use interface.

## Features

*   Comprehensive DNS record enumeration (A, AAAA, MX, TXT, CNAME, etc.)
*   WHOIS information gathering
*   Email security checks (SPF, DMARC)
*   HTTP security header analysis
*   SSL/TLS certificate inspection
*   And many more...

## Usage

```bash
python zone_poker.py <domain> [options]
```

### Output Formats

You can specify the output format using the `-o` or `--output` flag.

*   **txt**: (Default) A simple text file containing the full report.
*   **json**: A machine-readable JSON file with all the scan data.
*   **csv**: A detailed CSV export, with each section in its own format.
*   **html**: A self-contained HTML report with rich formatting.
*   **xml**: An XML file with the scan data.
*   **yaml**: A human-readable YAML file with all the scan data.

Example: `python zone_poker.py example.com -o yaml`
