# Zone-Poker

**Zone-Poker** is a powerful and feature-rich DNS intelligence and reconnaissance tool. It is designed to provide a comprehensive overview of a domain's DNS configuration, security posture, and related OSINT data from a single command.

The tool gathers data from various sources, analyzes it, and presents it in a clean, human-readable format in your terminal, while also exporting the complete findings to JSON and TXT files for easy record-keeping and further analysis.

---

## ✨ Key Features

- **Comprehensive DNS Enumeration**: Queries over a dozen record types, including `A`, `AAAA`, `MX`, `NS`, `SOA`, `TXT`, `SRV`, and more.
- **Zone Transfer Attempts (AXFR)**: Tries to perform a DNS zone transfer against each authoritative nameserver.
- **Email Security Analysis**: Checks for `SPF`, `DMARC`, and `DKIM` records and analyzes SPF record mechanisms for potential misconfigurations.
- **WHOIS & IP Intelligence**: Fetches `WHOIS` data for the domain and runs `IPWHOIS` lookups on discovered IP addresses.
- **Nameserver Analysis**: Gathers information about the domain's nameservers.
- **Technology Detection**: Identifies web technologies running on the domain's HTTP/HTTPS services.
- **Security Audit**: Performs basic security checks.
- **OSINT Enrichment**: Gathers related data from open-source intelligence sources.
- **Rich Console Output**: Uses `rich` to display results in beautifully formatted tables, trees, and panels.
- **Data Export**: Automatically exports all findings to structured `JSON` and detailed `TXT` reports on your Desktop.

---

## 🚀 Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/Zone-Poker.git
    cd Zone-Poker
    ```

2.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: If `requirements.txt` is not present, create it with `dnspython`, `requests`, `whois`, `ipwhois`, `rich`, and `beautifulsoup4` listed.)*

---

## Usage & Options

Run the `run_dnsint.py` script against a target domain. The script will orchestrate the different analysis, display, and export modules.

```bash
python3 run_dnsint.py <domain> [options]
```

**Example:**
```bash
python3 main.py example.com --verbose
```

---

## 📁 Exporting Results

All scans automatically generate two report files on your Desktop, timestamped for uniqueness:

- **`{domain}_dnsint_{timestamp}.json`**: A structured JSON file containing all the raw data gathered during the scan. Ideal for programmatic access or ingestion into other tools.
- **`{domain}_dnsint_{timestamp}.txt`**: A detailed text report that mirrors the information displayed in the console, suitable for manual review and sharing.

---

## License

This project is licensed under the Apache Version 2.0 License. See the `LICENSE` file for details.