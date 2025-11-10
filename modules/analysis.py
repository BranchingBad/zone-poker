#!/usr/bin/env python3
"""
Zone-Poker - Analysis Module
Contains all functions for data gathering and processing.
"""
import json
import socket
import re
import argparse # Added for type hinting
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
import dns.asyncquery # Correctly imported
import httpx
import whois as whois_lib
from ipwhois import IPWhois
from rich.progress import Progress, SpinnerColumn, TextColumn
from bs4 import BeautifulSoup

# Import shared config and utilities
from .config import console, RECORD_TYPES, PUBLIC_RESOLVERS
# --- THIS LINE IS UPDATED ---
from .utils import join_txt_chunks, get_parent_zone, _format_rdata, _parse_spf_record

# --- Helper Functions (REMOVED) ---
# _format_rdata and _parse_spf_record have been moved to utils.py

# --- Analysis Functions ---

async def get_dns_records(domain: str, resolver: dns.resolver.Resolver, verbose: bool, record_types: Optional[List[str]] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Asynchronously queries for multiple DNS record types for a given domain.
    Uses the provided centralized resolver.
    Can optionally query only for specific record types.
    """
    # Resolver is now passed in
    records = {}
    
    # If no specific types are given, use the default list from config
    types_to_query = record_types if record_types else RECORD_TYPES

    async def query_type(rtype: str):
        """Inner function to query a single record type."""
        try:
            answers = await resolver.resolve_async(domain, rtype)
            record_list = []
            for rdata in answers:
                record_info = _format_rdata(rtype, rdata, answers.ttl)
                record_list.append(record_info)
            records[rtype] = record_list
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
            records[rtype] = []
            if verbose:
                console.print(f"Error querying {rtype} for {domain}: {e}")

    # Use the new list to create the asyncio tasks
    await asyncio.gather(*(query_type(rtype) for rtype in types_to_query))
    return records

async def reverse_ptr_lookups(records: Dict[str, List[Dict[str, Any]]], resolver: dns.resolver.Resolver, verbose: bool) -> Dict[str, str]:
    """
    Performs reverse DNS (PTR) lookups for all A and AAAA records found.
    Uses the provided centralized resolver.
    """
    ptr_results = {}
    ips_to_check = []
    for rtype in ("A", "AAAA"):
        for record in records.get(rtype, []):
            if record.get("value"):
                ips_to_check.append(record["value"])

    # Resolver is now passed in

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

async def attempt_axfr(domain: str, records: Dict[str, List[Dict[str, Any]]], resolver: dns.resolver.Resolver, timeout: int, verbose: bool) -> Dict[str, Any]:
    """
    Attempts a zone transfer (AXFR) against all authoritative nameservers.
    Checks both A and AAAA records for nameservers.
    """
    axfr_results = {"status": "Not Attempted", "servers": {}}
    ns_records = records.get("NS", [])
    if not ns_records:
        axfr_results["status"] = "Skipped (No NS records found)"
        # --- THIS IS THE CORRECTED LINE ---
        return axfr_results

    nameservers = [record["value"] for record in ns_records]
    axfr_results["status"] = "Completed"
    
    async def try_axfr(ns):
        # Resolver is passed in
        ns_ips = []
        try:
            # Get A records
            a_answers = await resolver.resolve_async(ns, "A")
            ns_ips.extend([str(a) for a in a_answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass # No A records, try AAAA
        
        try:
            # Get AAAA records
            aaaa_answers = await resolver.resolve_async(ns, "AAAA")
            ns_ips.extend([str(a) for a in aaaa_answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass # No AAAA records
            
        if not ns_ips:
            axfr_results["servers"][ns] = {"status": "Failed (No A/AAAA record for NS)"}
            return

        for ns_ip in ns_ips:
            try:
                # Attempt transfer
                zone = await dns.zone.from_xfr(await dns.asyncquery.xfr(ns_ip, domain, timeout=timeout))
                
                nodes = zone.nodes.keys()
                axfr_results["servers"][ns] = {
                    "status": "Successful",
                    "ip_used": ns_ip,
                    "record_count": len(nodes),
                    "records": [str(n) for n in nodes]
                }
                return # Success, no need to try other IPs for this NS
            except dns.exception.FormError:
                axfr_results["servers"][ns] = {"status": "Failed (Refused)", "ip_tried": ns_ip}
            except (dns.exception.Timeout, asyncio.TimeoutError):
                axfr_results["servers"][ns] = {"status": "Failed (Timeout)", "ip_tried": ns_ip}
            except Exception as e:
                axfr_results["servers"][ns] = {"status": f"Failed ({type(e).__name__})", "ip_tried": ns_ip}
                if verbose:
                    console.print(f"AXFR error for {ns} at {ns_ip}: {e}")

    await asyncio.gather(*(try_axfr(ns) for ns in nameservers))
    
    if any(s.get("status") == "Successful" for s in axfr_results["servers"].values()):
        axfr_results["summary"] = "Vulnerable (Zone Transfer Successful)"
    else:
        axfr_results["summary"] = "Secure (No successful transfers)"
        
    return axfr_results

async def email_security_analysis(domain: str, records: Dict[str, List[Dict[str, Any]]], resolver: dns.resolver.Resolver) -> Dict[str, Any]:
    """Analyzes email security records (SPF, DMARC, DKIM)."""
    analysis = {}
    # Resolver is passed in

    # SPF (No network call needed, uses existing records)
    spf_records = [r["value"] for r in records.get("TXT", []) if r["value"].startswith("v=spf1")]
    if spf_records:
        analysis["spf"] = _parse_spf_record(spf_records[0])
        if len(spf_records) > 1:
            analysis["spf"]["warning"] = "Multiple SPF records found. Only one is allowed."
    else:
        analysis["spf"] = {"status": "Not Found"}

    # DMARC
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = [r["value"] for r in records.get("TXT", []) if r.get("value", "").startswith("v=DMARC1")]
    
    # If not on root, check the _dmarc subdomain asynchronously
    if not dmarc_records:
         try:
            # CHANGED: Switched to passed-in async resolver
            answers = await resolver.resolve_async(dmarc_domain, "TXT")
            dmarc_records = [join_txt_chunks([t.decode('utf-8', 'ignore') for t in rdata.strings]) for rdata in answers]
         except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            dmarc_records = []
    
    if dmarc_records:
        analysis["dmarc"] = {"raw": dmarc_records[0]}
        for part in dmarc_records[0].split(";"):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                analysis["dmarc"][key] = value
    else:
        analysis["dmarc"] = {"status": "Not Found"}

    # DKIM (cannot be checked reliably without a selector)
    analysis["dkim"] = {"status": "Cannot check without selector (e.g., 'default._domainkey')"}

    return analysis

async def whois_lookup(domain: str, verbose: bool) -> Dict[str, Any]:
    """
    Performs an async-friendly WHOIS lookup by running the blocking
    'whois' library in a separate thread.
    """
    try:
        whois_data = await asyncio.to_thread(whois_lib.whois, domain)
        
        if whois_data and whois_data.get('domain_name'):
            # Convert datetime objects to strings for JSON serialization
            return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in whois_data.items()}
        else:
            return {"error": "No WHOIS data returned."}
    except Exception as e:
        if verbose:
            console.print(f"[bold red]Error in whois_lookup: {e}[/bold red]")
        return {"error": str(e)}

async def nameserver_analysis(records: Dict[str, List[Dict[str, Any]]], resolver: dns.resolver.Resolver, verbose: bool) -> Dict[str, Any]:
    """Analyzes nameservers, checking IPs (A and AAAA) and DNSSEC support."""
    ns_info = {}
    ns_records = records.get("NS", [])
    if not ns_records:
        return {"error": "No NS records found."}

    # Resolver is passed in
    
    async def analyze_ns(ns_record):
        ns_name = ns_record["value"]
        info = {"ips": []}
        ns_ips = []
        try:
            # Get A records
            a_answers = await resolver.resolve_async(ns_name, "A")
            ns_ips.extend([str(a) for a in a_answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass # No A records
        
        try:
            # Get AAAA records
            aaaa_answers = await resolver.resolve_async(ns_name, "AAAA")
            ns_ips.extend([str(a) for a in aaaa_answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass # No AAAA records

        if not ns_ips:
            info["error"] = "No A or AAAA records found for NS"
            ns_info[ns_name] = info
            return

        # Just analyze the first IP found for ASN, etc.
        # A more complex implementation could check all IPs.
        first_ip = ns_ips[0]
        info["ips"] = ns_ips
        
        try:
            obj = IPWhois(first_ip)
            ip_whois_data = await asyncio.to_thread(obj.lookup_rdap, inc_raw=False)
            
            if ip_whois_data:
                info["asn"] = ip_whois_data.get("asn", "N/A")
                info["asn_registry"] = ip_whois_data.get("asn_registry", "N/A")