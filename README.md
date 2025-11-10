# Zone-Poker

**Zone-Poker** is a powerful and feature-rich DNS intelligence and reconnaissance tool. It is designed to provide a comprehensive overview of a domain's DNS configuration, security posture, and related OSINT data from a single, easy-to-use command.

The tool gathers data from various sources, analyzes it, and presents it in a clean, human-readable format in your terminal, while also exporting the complete findings to JSON and TXT files for easy record-keeping and further analysis.

---

## ✨ Key Features

- **Comprehensive DNS Record Enumeration**: Queries over a dozen record types, including `A`, `AAAA`, `MX`, `NS`, `SOA`, `TXT`, `SRV`, `CAA`, and more.
- **Reverse DNS Lookups**: Automatically performs PTR lookups for discovered `A` and `AAAA` records.
- **Zone Transfer Attempts (AXFR)**: Tries to perform a DNS zone transfer against each authoritative nameserver.
- **Email Security Analysis**: Checks for `SPF`, `DMARC`, and `DKIM` records and analyzes SPF record mechanisms for potential misconfigurations.
- **WHOIS & IP Intelligence**: Fetches `WHOIS` data for the domain and runs `IPWHOIS` lookups on discovered IP addresses.
- **Nameserver & DNSSEC Analysis**: Gathers information about the domain's nameservers and checks for DNSSEC records (`DNSKEY`, `DS`).
- **Global DNS Propagation Check**: Verifies DNS resolution against common public resolvers (Google, Cloudflare, Quad9).
- **Technology Detection**: Identifies web technologies, server types, and security headers on the domain's HTTP/HTTPS services.
- **Security Audit**: Performs basic security checks for common DNS misconfigurations.
- **OSINT Enrichment**: Gathers related data from open-source intelligence sources.
- **Rich Console Output**: Uses the `rich` library to display results in beautifully formatted tables, trees, and panels.
- **Configuration File**: Use a JSON config file to manage all your scan options for repeatable analysis.
- **Bulk Analysis**: Scan multiple domains at once by providing a JSON file.
- **Data Export**: Automatically exports all findings to structured `JSON` and detailed `TXT` reports on your Desktop.

---

## 🚀 Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/Zone-Poker.git
    cd zone-poker
    ```

2.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt # or pip install dnspython requests whois ipwhois rich beautifulsoup4
    ```

---

## Usage & Options

Run the `zone-poker.py` script against a single target domain or provide a file with a list of domains. If no specific modules are selected, a full scan is performed.

```bash
# Scan a single domain
python3 zone-poker.py <domain> [options]

# Scan multiple domains from a JSON file
python3 zone-poker.py -f domains.json [options]

# Use a configuration file to define scan parameters
python3 zone-poker.py -c my-scan.json
```

**Example:**
```bash
python3 zone-poker.py example.com --verbose
```

---

## 📁 Exporting Results

All scans automatically generate two report files on your Desktop, timestamped for uniqueness:

- **`{domain}_dnsint_{timestamp}.json`**: A structured JSON file containing all the raw data gathered during the scan. Ideal for programmatic access or ingestion into other tools.
- **`{domain}_dnsint_{timestamp}.txt`**: A detailed text report that mirrors the information displayed in the console, suitable for manual review and sharing.

---

## License

This project is licensed under the Apache Version 2.0 License. See the `LICENSE` file for details.