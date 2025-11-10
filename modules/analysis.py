#!/usr/bin/env python3
"""
Zone-poker - Analysis Module
Contains all functions for data gathering and processing.
"""
import json
import socket
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
import asyncio

import dns.resolver
import dns.query
import dns.zone
import dns.exception
import dns.reversename
import dns.message
import dns.rdatatype
import requests
import whois as whois_lib
from ipwhois import IPWhois
from rich.progress import Progress, SpinnerColumn, TextColumn
from bs4 import BeautifulSoup

# Import shared config and utilities
from .config import console, RECORD_TYPES, PUBLIC_RESOLVERS
from .utils import join_txt_chunks, get_parent_zone

# --- All your data-gathering functions go here ---
# (detect_technologies, get_dns_records, reverse_ptr_lookups,
# attempt_axfr, count_spf_lookups, email_security_analysis,
# whois_lookup, nameserver_analysis, propagation_check,
# security_audit, osint_enrichment)
 
# Example:
async def get_dns_records(domain: str, timeout: int, verbose: bool) -> Dict[str, List[Any]]:
    """Query all major DNS record types"""
    resolver = aiodns.DNSResolver()
    resolver.timeout = timeout
    records = {}

    async def query_type(rtype: str):
        try:
            # aiodns doesn't have a direct equivalent of dnspython's resolve that gives TTL easily,
            # so we use the lower-level query method.
            answers = await resolver.query(domain, rtype)
            record_list = []
            # For TTL, a separate query for the RRset would be needed, or we can omit it for simplicity in async context.
            # Here, we'll focus on the values first.
            for rdata in answers:
                record_info = {}
                if rtype == "MX":
                    record_info = {
                        "value": str(rdata.host),
                        "priority": rdata.priority,
                        "ttl": "N/A" # TTL is harder to get consistently in aiodns
                    }
                elif rtype == "SRV":
                     record_info = {
                        "value": str(rdata.host),
                        "priority": rdata.priority,
                        "weight": rdata.weight,
                        "port": rdata.port,
                        "ttl": "N/A"
                    }
                else:
                    # aiodns returns different object types
                    value = rdata.text if rtype == "TXT" else rdata.host if hasattr(rdata, 'host') else str(rdata)
                    record_info = {"value": value, "ttl": "N/A"}

                record_list.append(record_info)
            records[rtype] = record_list
        except (aiodns.error.DNSError) as e:
            records[rtype] = []
            if verbose:
                console.print(f"Error querying {rtype} for {domain}: {e}")

    await asyncio.gather(*(query_type(rtype) for rtype in RECORD_TYPES))
    return records

async def reverse_ptr_lookups(records: Dict[str, List[Dict[str, Any]]], timeout: int, verbose: bool) -> Dict[str, str]:
    """Perform reverse PTR lookups for A and AAAA records."""
    ptr_results = {}
    ips_to_check = []
    if records.get("A"):
        ips_to_check.extend([rec.get("value") for rec in records["A"]])
    if records.get("AAAA"):
        ips_to_check.extend([rec.get("value") for rec in records["AAAA"]])

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    async def query_ptr(ip):
        try:
            reversed_ip = dns.reversename.from_address(ip)
            answer = await resolver.resolve_async(reversed_ip, 'PTR')
            ptr_results[ip] = str(answer[0])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.exception.SyntaxError):
            ptr_results[ip] = "No PTR record found."
        except Exception as e:
            ptr_results[ip] = f"Error: {e}"

    await asyncio.gather(*(query_ptr(ip) for ip in ips_to_check if ip))
    return ptr_results

# ...
# ... (Copy ALL other analysis functions here)
# ... (detect_technologies, reverse_ptr_lookups, etc.)
# ...