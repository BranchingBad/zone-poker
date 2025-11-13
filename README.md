# Zone-Poker

**A professional DNS reconnaissance and OSINT tool for comprehensive domain analysis.**

Zone-Poker is a powerful, all-in-one command-line tool designed for security professionals, system administrators, and researchers to perform in-depth analysis of a domain's DNS and web infrastructure. It aggregates data from dozens of modules to provide a holistic view of a target's configuration and security posture.

![Zone-Poker Demo](https://user-images.githubusercontent.com/12345/placeholder.gif) <!-- TODO: Replace with an actual demo GIF -->


## Features

Zone-Poker combines numerous reconnaissance techniques into a single, fast, and extensible tool.

### DNS Analysis
- **DNS Records**: Queries for all common record types (A, AAAA, MX, TXT, CNAME, SOA, NS, etc.).
- **Reverse DNS**: Performs PTR lookups for discovered IP addresses.
- **Zone Transfer (AXFR)**: Attempts to perform a full zone transfer against the domain's nameservers.
- **Nameserver Analysis**: Gathers information about nameservers, their IPs, and ASN details.
- **DNSSEC Validation**: Checks if DNSSEC is enabled for the domain.
- **DNS Propagation**: Checks DNS resolution consistency across multiple public resolvers.
- **DANE/TLSA Records**: Looks for records related to DNS-Based Authentication of Named Entities.
- **Critical Findings Summary**: Automatically flags and summarizes the most critical issues at the top of the report, such as zone transfer vulnerabilities, expired certificates, and potential subdomain takeovers.

### Security & Vulnerability Analysis
- **Email Security**: Analyzes SPF, DMARC, and DKIM configurations.
- **SSL/TLS Analysis**: Inspects the SSL certificate, including validity, issuer, and Subject Alternative Names (SANs).
- **HTTP Security Headers**: Checks for the presence and configuration of key security headers.
- **Subdomain Takeover**: Scans CNAME records for fingerprints of services vulnerable to takeover.
- **Cloud Enumeration**: Discovers potential public S3 buckets and Azure Blob containers using a comprehensive set of domain permutations.
- **IP Reputation**: Checks IP addresses against the AbuseIPDB blocklist (requires API key).
- **DNS Blocklist (DNSBL)**: Checks discovered IPs against common real-time spam blocklists.
- **Open Port Scan**: Scans for common open TCP ports on discovered IP addresses.
- **WAF Detection**: Attempts to identify any Web Application Firewall (WAF) in use based on response headers and behavior.
- **Comprehensive Security Audit**: Performs a detailed audit for dozens of security misconfigurations, including permissive SPF policies, weak DMARC, zone transfer vulnerabilities, expired SSL certificates, insecure HTTP headers, and potential subdomain takeovers. Findings are categorized by severity (Critical, High, Medium, Low).
- **Open Redirect**: Checks for common open redirect vulnerabilities on the domain's root.

### OSINT & Enumeration
- **WHOIS Lookup**: Retrieves detailed registration information for the domain.
- **Technology Detection**: Identifies web server software, frameworks, and other technologies.
- **OSINT Enrichment**: Gathers subdomains and passive DNS data from external sources (e.g., AlienVault OTX).
- **Certificate Transparency**: Finds subdomains by comprehensively searching CT logs for both base domain and wildcard results.
- **IP Geolocation**: Determines the physical location, city, and ISP of IP addresses.
- **Content Hashing**: Calculates Murmur32 (favicon) and SHA256 (page content) hashes for hunting related infrastructure.

---

## Getting Started

Follow these steps to install Zone-Poker and run your first scan.

### 1. Prerequisites

- Python 3.10+
- Git

### 2. Installation

We recommend installing Zone-Poker in a virtual environment to avoid conflicts with other system packages.

```bash
# 1. Clone the repository from GitHub
git clone https://github.com/BranchingBad/zone-poker.git
cd zone-poker

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install the project and its dependencies
pip install .
```

### 3. Running Your First Scan

You can now run Zone-Poker directly from your command line.

**Run a basic scan for DNS records and WHOIS information:**
```bash
zone-poker example.com --records --whois
```

**Run a comprehensive scan using all modules:**
```bash
zone-poker example.com --all
```

### 4. Exporting Reports

To save the results, use the `--export` flag. This will create `.json` and `.txt` files in a new directory on your Desktop.

```bash
# Run all modules and save the reports
zone-poker example.com --all --export

# Save reports to a specific directory
zone-poker example.com --all --export -O /tmp/my-scan-reports
```

---

## Using with Docker

For users who prefer containerized workflows, Zone-Poker is available as a Docker image on the GitHub Container Registry (GHCR). This allows you to run the tool without installing Python or any dependencies on your host machine.

### 1. Pull the Image

Pull the latest stable image from GHCR:
```bash
docker pull ghcr.io/branchingbad/zone-poker:latest
```

### 2. Basic Usage

Run a scan by passing the arguments directly to the container. The command is the same as the local version, just prefixed by `docker run --rm -it ghcr.io/branchingbad/zone-poker:latest`:
```bash
docker run --rm -it ghcr.io/branchingbad/zone-poker:latest example.com --all
```

### 3. Using Local Files (Configuration & Reports)

To use local files like a configuration file or to save reports, you need to mount a local directory into the container as a volume.

**Example with a config file and exported reports:**

This command mounts your current working directory (`$(pwd)`) to the `/app` directory inside the container.

```bash
# Create a reports directory
mkdir -p my-reports

# Run the scan, mounting the current directory
docker run --rm -it -v "$(pwd):/app" ghcr.io/branchingbad/zone-poker:latest \
  example.com --all --export -O /app/my-reports
```
After the scan, your reports will be available in the `my-reports` directory on your host machine.

---

## Options

### Input Configuration
| Argument | Description |
| :--- | :--- |
| `domain` | Target domain to analyze (e.g., example.com). |
| `-f`, `--file` | Path to a file (JSON or YAML) containing a list of domains to analyze. |
| `-c`, `--config` | Path to a JSON or YAML config file with scan options. |

### Scan Control
| Flag | Description |
| :--- | :--- |
| `-a`, `--all` | Run all available analysis modules. |
| `--timeout` | Set network request timeout in seconds (default: 5). |
| `--retries` | Number of times to retry a failed domain scan (default: 0). |
| `--types` | Comma-separated list of DNS record types to query (e.g., 'A,MX,TXT'). |

### Output Control
| Flag | Description |
| :--- | :--- |
| `-e`, `--export` | Export JSON and TXT reports to your Desktop or a specified directory. |
| `--filename-template` | Template for report filenames. Use `{domain}` and `{timestamp}`. |
| `-O`, `--output-dir` | Directory to save exported reports. |
| `--html-file` | Path to save the HTML report directly to a file. |
| `--output` | Console output format. Choices: `table`, `json`, `csv`, `xml`, `html`, `txt`. |
| `-q`, `--quiet` | Show minimal console output (suppresses tables and headers). |
| `-v`, `--verbose` | Show detailed error logs during the scan. |
| `--log-file` | Path to a file to save detailed, verbose logs. |

### Analysis Modules
| Flag | Description |
| :--- | :--- |
| `-r`, `--records` | Query all standard DNS record types. |
| `--ptr` | Perform reverse DNS (PTR) lookups for A/AAAA records. |
| `-z`, `--zone` | Attempt a zone transfer (AXFR) against nameservers. |
| `-m`, `--mail` | Analyze email security records (SPF, DMARC, DKIM). |
| `-w`, `--whois` | Perform an extended WHOIS lookup on the domain. |
| `-n`, `--nsinfo` | Analyze nameserver information and check for DNSSEC. |
| `-p`, `--propagation` | Check DNS propagation across public resolvers. |
| `-s`, `--security` | Run a comprehensive audit for security misconfigurations. |
| `-t`, `--tech` | Detect web server software, frameworks, and other technologies. |
| `-o`, `--osint` | Enrich data with passive DNS and other OSINT sources. |
| `--ssl` | Analyze the SSL/TLS certificate. |
| `--smtp` | Analyze mail servers (banner, STARTTLS). |
| `--reputation` | Check IP reputation using AbuseIPDB. |
| `--hashes` | Get Murmur32 favicon and SHA256 page content hashes. |
| `--ct` | Finds subdomains by comprehensively searching Certificate Transparency logs. |
| `--waf` | Attempt to identify a Web Application Firewall. |
| `--dane` | Check for DANE (TLSA) records for HTTPS. |
| `--geo` | Geolocate IP addresses from A/AAAA records. |
| `--headers` | Perform an in-depth analysis of HTTP security headers. |
| `--ports` | Scan for common open TCP ports on discovered IPs. |
| `--takeover` | Check for potential subdomain takeovers. |
| `--cloud` | Enumerate potential cloud storage (S3, Azure Blobs) using comprehensive domain permutations. |
| `--dnsbl` | Check discovered IPs against common DNS blocklists. |
| `--security-txt` | Check for a `security.txt` file and parse its contents. |
| `--redirect` | Check for common open redirect vulnerabilities. |

---

## Configuration File

You can use a YAML or JSON configuration file to manage your scan settings. This is especially useful for setting up complex or repeated scans, managing API keys securely, and avoiding long command-line strings.

### Configuration Priority

The settings are applied in the following order of precedence, with later settings overriding earlier ones:
1.  **Tool Defaults**: The built-in default values.
2.  **Configuration File**: Values loaded from your `config.yaml` or `config.json` file.
3.  **Command-Line Arguments**: Any flags you provide when running the command will always have the final say.

For example, if your config file has `timeout: 10` but you run `zone-poker example.com --timeout 5`, the timeout used for the scan will be `5`.

### Example `config.yaml`

Here is a comprehensive example demonstrating how to set various options. The keys in the file should match the long-form command-line arguments, but with underscores instead of hyphens (e.g., `--output-dir` becomes `output_dir`).

```yaml
# Zone-Poker Sample Configuration File

# --- Input ---
# Specify a single domain or a file containing a list of domains.
# These are overridden by a domain or -f/--file argument on the command line.
# domain: "example.com"
# file: "domains.txt"

# --- API Keys ---
# Store API keys here to be used by relevant modules.
api_keys:
  abuseipdb: "YOUR_ABUSEIPDB_API_KEY"
  otx: "YOUR_ALIENVAULT_OTX_API_KEY"

# --- Scan Control ---
timeout: 10
retries: 1

# --- Output Control ---
export: true
output_dir: "~/Desktop/Zone-Poker-Reports"
filename_template: "{domain}_{timestamp}"
output: "table" # Console output format
verbose: false

# --- Analysis Modules ---
# Enable specific modules. This is equivalent to using flags like --whois, --ssl, etc.
all: false # Set to true to run all modules

records: true
whois: true
mail: true
ssl: true
security: true
```

**Usage:**
```bash
zone-poker -c config.yaml example.com
```

---

## Output Formats

Zone-Poker supports multiple output formats for both console display and file exports.
- **Console Output**: Use the `--output` flag to print results to the console in `table` (default), `json`, `csv`, `xml`, `html`, or `txt` format.
- **File Exports**:
  - Use the `--export` flag to save `json` and `txt` reports to your Desktop or a directory specified with `-O`.
  - Use the `--html-file` argument to save a comprehensive, self-contained HTML report to a specific file path.
  - The `csv` and `xml` formats can be redirected to a file (e.g., `zone-poker example.com --all --output csv > report.csv`).

---

## Troubleshooting

If you encounter issues, here are some common problems and their solutions:

*   **Modules Failing Due to Missing API Keys**:
    *   **Problem**: Modules like `--reputation` (AbuseIPDB) or `--osint` (AlienVault OTX) fail with an "API key is missing" error.
    *   **Solution**: These modules require you to provide an API key. The recommended way is to add them to a `config.yaml` file and pass it with the `-c` flag. See the `config.yaml` example section for the correct structure.

*   **Network Timeouts or Connection Errors**:
    *   **Problem**: The scan fails with timeout errors, or no data is returned for certain modules. This can happen on slow networks or if a firewall is blocking requests.
    *   **Solution**: You can increase the network timeout using the `--timeout` flag. The default is 5 seconds. Try increasing it:
        ```bash
        zone-poker example.com --all --timeout 15
        ```

*   **Permission Denied When Exporting Reports**:
    *   **Problem**: The tool shows a "Permission denied" error when using `--export` or `--html-file`.
    *   **Solution**: By default, reports are saved to your Desktop. If the tool doesn't have permission to write there, specify a different directory where you have write access using the `-O` or `--output-dir` flag:
        ```bash
        zone-poker example.com --all --export -O /tmp/zone-poker-reports
        ```

*   **Getting More Detailed Error Information**:
    *   **Problem**: A module fails, but the reason isn't clear from the standard output.
    *   **Solution**: Use the `-v` or `--verbose` flag to print detailed error messages and stack traces to the console. For comprehensive debugging, save the entire log to a file with `--log-file`:
        ```bash
        zone-poker example.com --all -v --log-file error.log
        ```

---

## Contributing

Contributions are welcome! Whether it's reporting a bug, suggesting a new feature, or submitting a pull request, your help is appreciated. Please see the CONTRIBUTING.md file for detailed guidelines.

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.
