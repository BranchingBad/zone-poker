#!/usr/bin/env python3
"""
Zone-Poker - Analysis Module
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

def _format_rdata(rtype: str, rdata: Any, ttl: int) -> Dict[str, Any]:
    """
    Formats a single dnspython rdata object into a standardized dictionary.

    Args:
        rtype: The DNS record type (e.g., 'A', 'MX').
        rdata: The rdata object from dnspython.
        ttl: The TTL of the record set.

    Returns:
        A dictionary representing the record.
    """
    record_info = {"ttl": ttl}
    if rtype == "MX":
        record_info.update({
            "value": str(rdata.exchange),
            "priority": rdata.preference,
        })
    elif rtype == "SRV":
        record_info.update({
            "value": str(rdata.target),
            "priority": rdata.priority,
            "weight": rdata.weight,
            "port": rdata.port,
        })
    elif rtype == "TXT":
        record_info["value"] = join_txt_chunks([t.decode('utf-8', 'ignore') for t in rdata.strings])
    else:
        record_info["value"] = str(rdata)
    return record_info
 
# Example:
async def get_dns_records(domain: str, timeout: int, verbose: bool) -> Dict[str, List[Dict[str, Any]]]:
    """
    Asynchronously queries for multiple DNS record types for a given domain.

    Args:
        domain: The domain name to query.
        timeout: The timeout in seconds for each DNS query.
        verbose: If True, prints errors to the console.

    Returns:
        A dictionary where keys are record types (e.g., 'A', 'MX') and values are lists
        of dictionaries, with each dictionary representing a single DNS record.
        Example: {'A': [{'value': '1.2.3.4', 'ttl': 3600}]}
    """
    resolver = dns.resolver.Resolver()
    resolver.set_flags(0)  # Disable recursion if only authoritative answers are needed
    resolver.timeout = timeout
    resolver.lifetime = timeout
    records = {}

    async def query_type(rtype: str):
        """Inner function to query a single record type."""
        try:
            # Use dnspython's async resolver
            answers = await resolver.resolve_async(domain, rtype)
            record_list = []
            for rdata in answers:
                record_info = _format_rdata(rtype, rdata, answers.ttl)
                record_list.append(record_info)
            records[rtype] = record_list
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
            # It's common for a domain not to have all record types, so we just create an empty list.
            records[rtype] = []
            if verbose:
                console.print(f"Error querying {rtype} for {domain}: {e}")

    await asyncio.gather(*(query_type(rtype) for rtype in RECORD_TYPES))
    return records

async def reverse_ptr_lookups(records: Dict[str, List[Dict[str, Any]]], timeout: int, verbose: bool) -> Dict[str, str]:
    """
    Performs reverse DNS (PTR) lookups for all A and AAAA records found.

    Args:
        records: The dictionary of DNS records from get_dns_records.
        timeout: The timeout in seconds for each DNS query.
        verbose: If True, prints errors to the console.

    Returns:
        A dictionary mapping each IP address to its PTR record or an error message.
    """
    ptr_results = {}
    ips_to_check = []
    # Extract all 'value' fields (IP addresses) from the 'A' and 'AAAA' records lists
    for rtype in ("A", "AAAA"):
        for record in records.get(rtype, []):
            if record.get("value"):
                ips_to_check.append(record["value"])

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