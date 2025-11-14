# Zone-Poker

A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis.

## Description

Zone-Poker is a powerful and flexible tool designed for security professionals, system administrators, and researchers to perform in-depth DNS enumeration and gather open-source intelligence (OSINT) on a given domain. It consolidates multiple scanning techniques into a single, easy-to-use interface, allowing you to get a complete picture of a domain's configuration and security posture.

## Features

*   **Comprehensive DNS Enumeration**: Query over 20 DNS record types, including A, AAAA, MX, TXT, CNAME, and more.
*   **Security Audits**: Automatically scan for common misconfigurations like missing security headers, vulnerable services, and open redirects.
*   **OSINT Gathering**: Enrich findings with data from WHOIS lookups, Certificate Transparency logs, and IP reputation services.
*   **Email & Web Security**: Analyze SPF, DMARC, and DKIM records, inspect SSL/TLS certificates, and detect Web Application Firewalls (WAF).
*   **Advanced Analysis**: Attempt zone transfers, check for subdomain takeovers, and identify running web technologies.
*   **Flexible Output**: Generate reports in multiple formats, including human-readable tables, JSON, CSV, HTML, XML, and YAML.

## Getting Started

### Prerequisites

*   Python 3.8+
*   `pip` for installing dependencies

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/zone-poker.git
    cd zone-poker
    ```

2.  Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

### Basic Usage

To run a default scan against a single domain, simply provide the domain name:

```bash
python zone_poker.py example.com
```

This will run the essential checks and display the output in a clean, readable table format.

## Usage

The tool is highly configurable through command-line switches.

```
usage: zone_poker.py [-h] [--version] [domain] [-f FILE] [-c CONFIG] [-a] [--timeout TIMEOUT] [--retries RETRIES] [--types TYPES] [--resolvers RESOLVERS] [-e] [-O OUTPUT_DIR] [--filename-template FILENAME_TEMPLATE] [--html-file HTML_FILE] [--log-file LOG_FILE] [-v] [-q] [--output {table,json,csv,xml,html,txt,yaml}] ...

Zone-Poker - A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis.
Created by BranchingBad

Input Configuration:
  domain                Target domain to analyze (e.g., example.com)
  -f FILE, --file FILE  Path to a file (JSON or YAML) containing a list of domains to analyze.
  -c CONFIG, --config CONFIG
                        Path to a JSON or YAML config file with scan options.

Scan Control:
  -a, --all             Run all analysis modules.
  --timeout TIMEOUT     Set network request timeout in seconds (default: 5).
  --retries RETRIES     Number of times to retry a failed domain scan (default: 0).
  --types TYPES         Comma-separated list of DNS record types to query (e.g., 'A,MX,TXT').
  --resolvers RESOLVERS
                        Comma-separated list of custom DNS resolvers to use.

Output Control:
  -e, --export          Export default reports (.json, .txt).
  -O OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Directory to save reports (defaults to Desktop).
  --filename-template FILENAME_TEMPLATE
                        Template for report filenames. Default: '{domain}_dnsint_{timestamp}'.
  --html-file HTML_FILE
                        Export an HTML report to the specified file path.
  --log-file LOG_FILE   Path to a file to save detailed, verbose logs.
  -v, --verbose         Show detailed error logs during the scan.
  -q, --quiet           Show minimal console output (suppresses tables and headers).
  --output {table,json,csv,xml,html,txt,yaml}
                        Console output format. 'table' for human-readable, others for machine-readable.
```

## Analysis Modules

You can run specific analysis modules using their corresponding flags.

| Flag (Short) | Flag (Long)      | Description                                                 |
|--------------|------------------|-------------------------------------------------------------|
| `-r`         | `--records`      | Query all standard DNS record types.                        |
|              | `--ptr`          | Perform reverse DNS (PTR) lookups for A/AAAA records.       |
| `-z`         | `--zone`         | Attempt a zone transfer (AXFR) against nameservers.         |
| `-m`         | `--mail`         | Analyze email security records (SPF, DMARC, DKIM).          |
| `-w`         | `--whois`        | Perform an extended WHOIS lookup on the domain.             |
| `-n`         | `--nsinfo`       | Analyze nameserver information and check for DNSSEC.        |
| `-p`         | `--propagation`  | Check DNS propagation across public resolvers.              |
| `-s`         | `--security`     | Run a comprehensive audit for security misconfigurations.   |
| `-t`         | `--tech`         | Detect web technologies, CMS, and security headers.         |
|              | `--reputation`   | Check IP reputation using AbuseIPDB.                        |
|              | `--osint`        | Enrich data with passive DNS and other OSINT sources.       |
|              | `--ssl`          | Analyze the SSL/TLS certificate.                            |
|              | `--smtp`         | Analyze mail servers (banner, STARTTLS).                    |
|              | `--hashes`       | Get Murmur32 favicon and SHA256 page content hashes.        |
|              | `--ct`           | Find subdomains from Certificate Transparency logs.         |
|              | `--waf`          | Attempt to identify a Web Application Firewall.             |
|              | `--dane`         | Check for DANE (TLSA) records for HTTPS.                    |
|              | `--geo`          | Geolocate IP addresses from A/AAAA records.                 |
|              | `--headers`      | Perform an in-depth analysis of HTTP security headers.      |
|              | `--ports`        | Scan for common open TCP ports on discovered IPs.           |
|              | `--takeover`     | Check for potential subdomain takeovers.                    |
|              | `--cloud`        | Enumerate common cloud services (e.g., S3 buckets).         |
|              | `--dnsbl`        | Check discovered IPs against common DNS blocklists.         |
|              | `--redirect`     | Check for common open redirect vulnerabilities.             |
|              | `--security-txt` | Check for a security.txt file and parse its contents.       |
|              | `--robots`       | Check for a robots.txt file and analyze its contents.       |

## Examples

### Run a Full Scan and Export Reports

Run all analysis modules against a domain and save the results to `.txt` and `.json` files in a custom directory.

```bash
python zone_poker.py example.com --all --export -O /path/to/reports/
```

### Focus on Email Security

Check a domain's mail servers, security records (SPF, DMARC), and SMTP configuration.

```bash
python zone_poker.py example.com --mail --smtp
```

### Query Specific DNS Records

Look up only the A, MX, and TXT records for a domain.

```bash
python zone_poker.py example.com --records --types A,MX,TXT
```

### Generate an HTML Report

Run a security audit and export the findings to a self-contained HTML file.

```bash
python zone_poker.py example.com --security --html-file report.html
```

### Scan Multiple Domains from a File

Analyze a list of domains from a file and output the console results in JSON format.

```bash
# domains.txt
example.com
google.com
github.com
```

```bash
python zone_poker.py --file domains.txt --output json
```
