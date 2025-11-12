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

### Security & Vulnerability Analysis
- **Email Security**: Analyzes SPF, DMARC, and DKIM configurations.
- **SSL/TLS Analysis**: Inspects the SSL certificate, including validity, issuer, and Subject Alternative Names (SANs).
- **HTTP Security Headers**: Checks for the presence and configuration of key security headers.
- **Subdomain Takeover**: Scans CNAME records for fingerprints of services vulnerable to takeover.
- **Cloud Enumeration**: Discovers potential public S3 buckets and Azure Blob containers based on domain permutations.
- **IP Reputation**: Checks IP addresses against the AbuseIPDB blocklist (requires API key).
- **DNS Blocklist (DNSBL)**: Checks discovered IPs against common real-time spam blocklists.
- **Open Port Scan**: Scans for common open TCP ports on discovered IP addresses.
- **WAF Detection**: Attempts to identify any Web Application Firewall (WAF) in use.
- **General Security Audit**: Runs a series of checks for common misconfigurations.

### OSINT & Enumeration
- **WHOIS Lookup**: Retrieves detailed registration information for the domain.
- **Technology Detection**: Identifies web server software, frameworks, and other technologies.
- **OSINT Enrichment**: Gathers subdomains and passive DNS data from external sources (e.g., AlienVault OTX).
- **Certificate Transparency**: Finds subdomains by searching CT logs.
- **IP Geolocation**: Determines the physical location, city, and ISP of IP addresses.
- **Content Hashing**: Calculates Murmur32 (favicon) and SHA256 (page content) hashes for hunting related infrastructure.

---

## Installation

Zone-Poker can be installed directly from the cloned repository. It is recommended to use a virtual environment.

```bash
# Clone the repository
git clone https://github.com/BranchingBad/zone-poker.git
cd zone-poker
# Install the project and its dependencies
pip install .
```

## Usage

The simplest way to run a full scan on a domain is with the `--all` flag.

```bash
zone-poker example.com --all
```

### Examples

**Run all modules and export reports:**
```bash
zone-poker example.com --all --export
```

**Run specific modules and save reports to a custom directory:**
```bash
zone-poker example.com --mail --whois --export -O /path/to/reports/
```

**Query for specific DNS record types:**
```bash
zone-poker example.com --records --types A,MX,TXT
```

**Scan multiple domains from a file and generate an HTML report:**
```bash
zone-poker -f domains.txt --all --output html > report.html
```

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
| `--output` | Console output format. Choices: `table`, `json`, `csv`, `xml`, `html`. |
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
| `-s`, `--security` | Run a basic audit for DNS security misconfigurations. |
| `-t`, `--tech` | Detect web technologies, CMS, and security headers. |
| `-o`, `--osint` | Enrich data with passive DNS and other OSINT sources. |
| `--ssl` | Analyze the SSL/TLS certificate. |
| `--smtp` | Analyze mail servers (banner, STARTTLS). |
| `--reputation` | Check IP reputation using AbuseIPDB. |
| `--hashes` | Get Murmur32 favicon and SHA256 page content hashes. |
| `--ct` | Find subdomains from Certificate Transparency logs. |
| `--waf` | Attempt to identify a Web Application Firewall. |
| `--dane` | Check for DANE (TLSA) records for HTTPS. |
| `--geo` | Geolocate IP addresses from A/AAAA records. |
| `--headers` | Perform an in-depth analysis of HTTP security headers. |
| `--ports` | Scan for common open TCP ports on discovered IPs. |
| `--takeover` | Check for potential subdomain takeovers. |
| `--cloud` | Enumerate common cloud services (e.g., S3 buckets). |
| `--dnsbl` | Check discovered IPs against common DNS blocklists. |
| `--redirect` | Check for common open redirect vulnerabilities. |

---

## Output Formats

Zone-Poker supports multiple output formats for both console display and file exports.
- **JSON, CSV, XML, HTML**: Machine-readable formats that can be selected with the `--output` flag. By default, these are printed to standard output, but the HTML report can be saved directly to a file using the `--html-file` argument.


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
zone-poker example.com --all -c config.yaml
```

Command-line arguments will always override settings from a configuration file.

---

## Contributing

Contributions are welcome! Whether it's reporting a bug, suggesting a new feature, or submitting a pull request, your help is appreciated. Please see the CONTRIBUTING.md file for detailed guidelines.

## License

This project is licensed under the MIT License. See the LICENSE file for details.