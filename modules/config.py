#!/usr/bin/env python3
from rich.console import Console

# Initialize a single console object to be used by all modules
console = Console()

# DNS Record Types
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "NAPTR", "DNSKEY", "DS"]

# Public Resolvers
PUBLIC_RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9"
}