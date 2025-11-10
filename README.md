# Zone-Poker

**Zone-Poker** is a powerful and feature-rich DNS intelligence and reconnaissance tool. It is designed to provide a comprehensive overview of a domain's DNS configuration, security posture, and related OSINT data from a single, easy-to-use command.

The tool gathers data from various sources, analyzes it, and presents it in a clean, human-readable format in your terminal, while also exporting the complete findings to JSON and TXT files for easy record-keeping and further analysis.

---

## ✨ Key Features

- **Comprehensive DNS Record Enumeration**: Queries over a dozen record types, including `A`, `AAAA`, `MX`, `NS`, `SOA`, `TXT`, `SRV`, `CAA`, and more.
- **Reverse DNS Lookups**: Automatically performs PTR lookups for discovered `A` and `AAAA` records.
- **Zone Transfer Attempts (AXFR)**: Tries to perform a DNS zone transfer against each authoritative nameserver (over IPv4 and IPv6).
- **Email Security Analysis**: Checks for `SPF`, `DMARC`, and `DKIM` records and analyzes SPF record mechanisms for potential misconfigurations.
- **WHOIS & IP Intelligence**: Fetches `WHOIS` data for the domain and runs `IPWHOIS` lookups on discovered IP addresses.
- **Nameserver & DNSSEC Analysis**: Gathers information about the domain's nameservers (IPv4/IPv6) and checks for DNSSEC records (`DNSKEY`, `DS`).
- **Global DNS Propagation Check**: Verifies DNS resolution against common public resolvers (Google, Cloudflare, Quad9).
- **Technology Detection**: Identifies web technologies, server types, and security headers on the domain's HTTP/HTTPS services.
- **Security Audit**: Performs basic security checks for common DNS misconfigurations.
- **OSINT Enrichment**: Gathers related data from open-source intelligence sources (e.g., AlienVault OTX).
- **Rich Console Output**: Uses the `rich` library to display results in beautifully formatted tables, trees, and panels.
- **Configuration File**: Use a JSON config file to manage all your scan options and API keys.
- **Bulk Analysis**: Scan multiple domains at once by providing a JSON file.
- **Data Export**: Automatically exports all findings to structured `JSON` and detailed `TXT` reports to a configurable directory.

---

## 🚀 Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/Zone-Poker.git
    cd zone-poker
    ```

2.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

---

## Configuration

Zone-Poker can be configured using a JSON file (passed with `-c` or `--config`). This file can set any option that the command-line arguments can.

### Configuration Priority
The tool uses a 3-tiered priority system for settings:
1.  **Command-Line Arguments**: Highest priority. (e.g., `--timeout 10`)
2.  **Config File**: Medium priority. (e.g., `{"timeout": 5}`)
3.  **Program Defaults**: Lowest priority.

An argument on the command line will *always* override a setting in the config file.

### API Keys
For modules that use third-party APIs (like OSINT enrichment), you can provide API keys in your config file to avoid rate-limiting.

**Example `my-scan.json`:**
```json
{
  "timeout": 10,
  "verbose": true,
  "api_keys": {
    "otx": "your_alienvault_otx_api_key_here"
  }
}
```
## Usage & Options
### Basic Commands
```bash
# Scan a single domain with all modules and export
python3 zone-poker.py example.com --all --export

# Scan multiple domains from a JSON file
python3 zone-poker.py -f domains.json --all

# Use a configuration file to define scan parameters
python3 zone-poker.py -c my-scan.json

# Scan and save reports to a specific directory
python3 zone-poker.py example.com --all -e -O /home/user/reports/

# Query for only A and MX records
python3 zone-poker.py example.com -r --types A,MX
```

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

---

## 📁 Exporting Results

All scans automatically generate two report files on your Desktop, timestamped for uniqueness:

- **`{domain}_dnsint_{timestamp}.json`**: A structured JSON file containing all the raw data gathered during the scan. Ideal for programmatic access or ingestion into other tools.
- **`{domain}_dnsint_{timestamp}.txt`**: A detailed text report that mirrors the information displayed in the console, suitable for manual review and sharing.

---

## License

This project is licensed under the Apache Version 2.0 License. See the `LICENSE` file for details.