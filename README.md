# Zone-Poker

**Zone-Poker** is a powerful and feature-rich DNS intelligence and reconnaissance tool, designed to provide a comprehensive overview of a domain's DNS configuration, security posture, and related OSINT data from a single command.

The tool gathers data from various sources, analyzes it, and presents it in a clean, human-readable format in your terminal. It also exports the complete findings to `JSON` and `TXT` files for easy record-keeping and further analysis.

---

## ✨ Key Features

- **Comprehensive DNS Record Enumeration**: Queries over a dozen record types, including `A`, `AAAA`, `MX`, `NS`, `SOA`, `TXT`, `SRV`, `CAA`, and more.
- **Reverse DNS Lookups**: Automatically performs PTR lookups for discovered `A` and `AAAA` records.
- **Zone Transfer Attempts (AXFR)**: Tries to perform a DNS zone transfer against each authoritative nameserver over both IPv4 and IPv6.
- **Email Security Analysis**: Checks for `SPF`, `DMARC`, and `DKIM` records and analyzes their policies for potential misconfigurations.
- **WHOIS & IP Intelligence**: Fetches `WHOIS` data for the domain and runs `IPWHOIS` lookups on nameserver IP addresses to find ASN details.
- **SSL/TLS Certificate Analysis**: Retrieves and analyzes the SSL/TLS certificate for the domain, including validity, issuer, and Subject Alternative Names (SANs).
- **SMTP Server Analysis**: Connects to mail servers to check for STARTTLS support and retrieve banners.
- **Nameserver & DNSSEC Analysis**: Gathers information about the domain's nameservers (IPv4/IPv6) and checks for DNSSEC records (`DNSKEY`, `DS`).
- **Global DNS Propagation Check**: Verifies DNS resolution against common public resolvers (Google, Cloudflare, Quad9).
- **Technology Detection**: Identifies web technologies, server types, and security headers on the domain's HTTP/HTTPS services.
- **Security Audit**: Performs basic security checks for common DNS misconfigurations.
- **OSINT Enrichment**: Gathers related data from open-source intelligence sources (e.g., AlienVault OTX).
- **IP Reputation**: Checks the reputation of discovered IP addresses against the AbuseIPDB database.
- **Rich Console Output**: Uses the `rich` library to display results in beautifully formatted tables, trees, and panels.
- **Flexible Configuration**: Use a `JSON` config file to manage all your scan options and API keys, with a clear priority system (CLI > Config > Defaults).
- **Concurrent Bulk Analysis**: Scan multiple domains concurrently for significant performance gains.
- **Data Export**: Automatically exports all findings to structured `JSON` and detailed `TXT` reports to a configurable directory.
- **Resilient Scanning**: Automatically retry failed domain scans to handle transient network errors.
- **Advanced Logging**: Control console verbosity (`-v`, `-q`) and save detailed debug logs to a file (`--log-file`).

---

## 📋 Prerequisites

- Python 3.8+
- `pip` for installing dependencies

- Some modules require API keys for full functionality (e.g., AbuseIPDB, AlienVault OTX).

---

## 🚀 Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/wh0xac/zone-poker.git
    cd zone-poker
    ```

2.  Install the project and its dependencies. This will also make the `zone-poker` command available in your environment.
    ```bash
    pip install .
    ```

---
## ⚙️ Configuration

Zone-Poker can be configured using a `JSON` file (passed with `-c` or `--config`). This file can set any option that the command-line arguments can.
Zone-Poker can be configured using a `JSON` or `YAML` file (passed with `-c` or `--config`). This file can set any option that the command-line arguments can.

### Configuration Priority
The tool uses a 3-tiered priority system for settings, processed in the following order:
1.  **Program Defaults**: The lowest priority, built-in settings.
2.  **Config File**: Medium priority; values in the config file (e.g., `{"timeout": 5}`) override the defaults.
3.  **Command-Line Arguments**: The highest priority; flags explicitly set on the command line (e.g., `--timeout 10`) override both the config file and defaults.

An argument on the command line will *always* override a setting in the config file.

### API Keys
For modules that use third-party APIs (like OSINT enrichment), you can provide API keys in your config file to avoid rate-limiting.

**Example `config.yaml`:**
```jsonc
{
    "timeout": 10,
    "verbose": true,
    "api_keys": {
        "otx": "your_alienvault_otx_api_key_here",
        "abuseipdb": "your_abuseipdb_api_key_here"
    }
}
```
---
## 🚀 Usage

### Basic Commands
```bash
# Scan a single domain, run all modules, and export reports
zone-poker example.com --all --export

# Scan multiple domains from a file and run a security audit
zone-poker -f domains.json --security

# Use a configuration file to define scan parameters
zone-poker example.com -c my-scan.json

# Scan and save reports to a specific directory
zone-poker example.com --all --export -O /home/user/reports/

# Query for only A and MX records
zone-poker example.com --records --types A,MX

# Run a quiet scan but save all debug information to a log file
zone-poker example.com --all -q --log-file scan.log
```

## Command-Line Arguments
| Flag | Description |
|---|---|
| `-a`,	`--all` |	Run all analysis modules.
| `-e`,	`--export` |	Export JSON and TXT reports.
| `-O`,	`--output-dir` |	Path to a directory for saving reports (default: Desktop).
| `-c`,	`--config` |	Path to a JSON config file with scan options.
| `-f`,	`--file` |	Path to a JSON file containing a list of domains to analyze.
| `-v`,	`--verbose` |	Show detailed error logs and debug messages during the scan.
| `-q`,	`--quiet` |	Show minimal console output (suppresses tables, headers, and progress bars).
| `--log-file` | Path to a file to save detailed, verbose logs.
| `--timeout`	| Set the DNS query timeout in seconds (default: 5).
| `--retries` | Number of times to retry a failed domain scan (default: 0).
| `--types`	| Comma-separated list of specific DNS record types to query (e.g., `A,MX,TXT`).

## Analysis Modules

Run specific modules by adding their flags.

| Flag | Module | Description |
|---|---|---|
| `-r`, `--records` | Records | Query all standard DNS record types. |
| `--ptr` | PTR Lookups | Perform reverse DNS (PTR) lookups for A/AAAA records. |
| `-z`, `--zone` | Zone Transfer | Attempt a zone transfer (AXFR) against nameservers. |
| `-m`, `--mail` | Email Security | Analyze email security records (SPF, DMARC, DKIM). |
| `-w`, `--whois` | WHOIS | Perform an extended WHOIS lookup on the domain. |
| `-n`, `--nsinfo` | Nameserver Info | Analyze nameserver information and check for DNSSEC. |
| `-p`, `--propagation` | Propagation | Check DNS propagation across public resolvers. |
| `-s`, `--security` | Security Audit | Run a basic audit for DNS security misconfigurations. |
| `-t`, `--tech` | Tech Detection | Detect web technologies, CMS, and security headers. |
| `-o`, `--osint` | OSINT | Enrich data with passive DNS and other OSINT sources. |
| `--ssl` | SSL/TLS Analysis | Analyze the SSL/TLS certificate for the domain. |
| `--smtp` | SMTP Analysis | Analyze mail servers (banner, STARTTLS). |
| `--reputation` | IP Reputation | Check IP reputation using AbuseIPDB. |
| `--hashes` | Content Hashes | Get Murmur32 favicon and SHA256 page content hashes. |
| `--ct` | CT Log Analysis | Find subdomains from Certificate Transparency logs. |
| `--waf` | WAF Detection | Attempt to identify a Web Application Firewall. |
| `--dane` | DANE/TLSA Analysis | Check for DANE (TLSA) records for HTTPS. |
| `--geo` | IP Geolocation | Geolocate IP addresses from A/AAAA records. |
| `--headers` | HTTP Headers | Perform an in-depth analysis of HTTP security headers. |
| `--ports` | Port Scan | Scan for common open TCP ports on discovered IPs. |
| `--takeover` | Subdomain Takeover | Check for potential subdomain takeovers on CNAME records. |
| `--cloud` | Cloud Enumeration | Enumerate common cloud services (e.g., S3 buckets). |

---

## 📁 Exporting Results

All scans automatically generate two report files on your Desktop (or the directory specified with `-O`), timestamped for uniqueness:

`{domain}_dnsint_{timestamp}`.json: A structured JSON file containing all the raw data gathered during the scan. Ideal for programmatic access or ingestion into other tools.

`{domain}_dnsint_{timestamp}.txt`: A detailed text report that mirrors the information displayed in the console, suitable for manual review and sharing.

---

## ⚖️ License

This project is licensed under the Apache Version 2.0 License. See the `LICENSE` file for details.