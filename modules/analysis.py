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

async def get_dns_records(domain: str, timeout: int, verbose: bool) -> Dict[str, List[Dict[str, Any]]]:
    """
    Asynchronously queries for multiple DNS record types for a given domain.
    """
    resolver = dns.resolver.Resolver()
    resolver.set_flags(0)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    records = {}

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

    await asyncio.gather(*(query_type(rtype) for rtype in RECORD_TYPES))
    return records

async def reverse_ptr_lookups(records: Dict[str, List[Dict[str, Any]]], timeout: int, verbose: bool) -> Dict[str, str]:
    """
    Performs reverse DNS (PTR) lookups for all A and AAAA records found.
    """
    ptr_results = {}
    ips_to_check = []
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

async def attempt_axfr(domain: str, records: Dict[str, List[Dict[str, Any]]], timeout: int, verbose: bool) -> Dict[str, Any]:
    """Attempts a zone transfer (AXFR) against all authoritative nameservers."""
    axfr_results = {"status": "Not Attempted", "servers": {}}
    ns_records = records.get("NS", [])
    if not ns_records:
        axfr_results["status"] = "Skipped (No NS records found)"
        return axaxfr_results

    nameservers = [record["value"] for record in ns_records]
    axfr_results["status"] = "Completed"
    
    async def try_axfr(ns):
        try:
            # Get IP of nameserver
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            ns_answer = await resolver.resolve_async(ns, "A")
            ns_ip = str(ns_answer[0])

            # Attempt transfer
            zone = await dns.zone.from_xfr(await dns.asyncquery.xfr(ns_ip, domain, timeout=timeout))
            
            nodes = zone.nodes.keys()
            axfr_results["servers"][ns] = {
                "status": "Successful",
                "record_count": len(nodes),
                "records": [str(n) for n in nodes]
            }
        except dns.exception.FormError:
            axfr_results["servers"][ns] = {"status": "Failed (Refused)"}
        except (dns.exception.Timeout, asyncio.TimeoutError):
            axfr_results["servers"][ns] = {"status": "Failed (Timeout)"}
        except Exception as e:
            axfr_results["servers"][ns] = {"status": f"Failed ({type(e).__name__})"}
            if verbose:
                console.print(f"AXFR error for {ns}: {e}")

    await asyncio.gather(*(try_axfr(ns) for ns in nameservers))
    
    if any(s["status"] == "Successful" for s in axfr_results["servers"].values()):
        axfr_results["summary"] = "Vulnerable (Zone Transfer Successful)"
    else:
        axfr_results["summary"] = "Secure (No successful transfers)"
        
    return axfr_results

async def email_security_analysis(domain: str, records: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Analyzes email security records (SPF, DMARC, DKIM)."""
    analysis = {}
    resolver = dns.resolver.Resolver()

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
            # CHANGED: Switched to async resolver
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

async def nameserver_analysis(records: Dict[str, List[Dict[str, Any]]], timeout: int, verbose: bool) -> Dict[str, Any]:
    """Analyzes nameservers, checking IPs and DNSSEC support."""
    ns_info = {}
    ns_records = records.get("NS", [])
    if not ns_records:
        return {"error": "No NS records found."}

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    
    async def analyze_ns(ns_record):
        ns_name = ns_record["value"]
        info = {}
        try:
            # Get NS IP
            answers = await resolver.resolve_async(ns_name, "A")
            ip = str(answers[0])
            info["ip"] = ip
            
            obj = IPWhois(ip)
            ip_whois_data = await asyncio.to_thread(obj.lookup_rdap, inc_raw=False)
            
            if ip_whois_data:
                info["asn"] = ip_whois_data.get("asn", "N/A")
                info["asn_registry"] = ip_whois_data.get("asn_registry", "N/A")
                info["asn_cidr"] = ip_whois_data.get("asn_cidr", "N/A")
                info["asn_description"] = ip_whois_data.get("asn_description", "N/A")
        except Exception as e:
            info["error"] = str(e)
            if verbose:
                console.print(f"Error analyzing NS {ns_name}: {e}")
        ns_info[ns_name] = info

    await asyncio.gather(*(analyze_ns(ns) for ns in ns_records))
    
    # Check DNSSEC
    if records.get("DNSKEY") and records.get("DS"):
        ns_info["dnssec"] = "Enabled (DNSKEY and DS records found)"
    elif records.get("DNSKEY"):
        ns_info["dnssec"] = "Partial (DNSKEY found, but no DS record)"
    else:
        ns_info["dnssec"] = "Not Enabled (No DNSKEY or DS records)"
        
    return ns_info

async def propagation_check(domain: str, timeout: int) -> Dict[str, str]:
    """Checks domain 'A' record propagation against public resolvers."""
    results = {}
    
    async def check_resolver(name, ip):
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.nameservers = [ip]
        try:
            answers = await resolver.resolve_async(domain, "A")
            results[name] = str(answers[0])
        except Exception as e:
            results[name] = f"Error: {type(e).__name__}"
            
    await asyncio.gather(*(check_resolver(name, ip) for name, ip in PUBLIC_RESOLVERS.items()))
    return results

def security_audit(records: Dict[str, List[Dict[str, Any]]], email_security: Dict[str, Any]) -> Dict[str, str]:
    """Runs a basic audit for DNS security misconfigurations."""
    audit = {}
    
    # SPF Policy
    if email_security.get("spf", {}).get("all_policy") == "?all":
        audit["SPF Policy"] = "Weak (Using '?all' Neutral policy)"
    elif email_security.get("spf", {}).get("all_policy") == "~all":
        audit["SPF Policy"] = "Moderate (Using '~all' SoftFail policy)"
    elif email_security.get("spf", {}).get("all_policy") == "-all":
        audit["SPF Policy"] = "Secure (Using '-all' HardFail policy)"
    else:
        audit["SPF Policy"] = "Weak (No 'all' policy or record not found)"

    # DMARC Policy
    if email_security.get("dmarc", {}).get("p") == "none":
        audit["DMARC Policy"] = "Weak (Policy 'p=none' is in monitoring mode)"
    elif email_security.get("dmarc", {}).get("p") in ("quarantine", "reject"):
        audit["DMARC Policy"] = f"Secure (Policy 'p={email_security['dmarc']['p']}')"
    else:
        audit["DMARC Policy"] = "Not Found or Misconfigured"

    # CAA Record
    if records.get("CAA"):
        audit["CAA Record"] = "Present (Restricts certificate issuance)"
    else:
        audit["CAA Record"] = "Not Found (Any CA can issue certificates)"

    return audit

async def detect_technologies(domain: str, timeout: int, verbose: bool) -> Dict[str, Any]:
    """
    Detects web technologies, CMS, and security headers using async HTTP.
    """
    tech_data = {"headers": {}, "technologies": [], "server": "", "status_code": 0, "error": None}
    urls_to_check = [f"https://{domain}", f"http://{domain}"]
    
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for url in urls_to_check:
            try:
                response = await client.get(url)
                tech_data["status_code"] = response.status_code
                tech_data["server"] = response.headers.get("Server", "")
                
                # Simple header parsing
                headers = dict(response.headers)
                tech_data["headers"] = headers
                if headers.get("X-Powered-By"):
                    tech_data["technologies"].append(headers["X-Powered-By"])
                if headers.get("X-Generator"):
                    tech_data["technologies"].append(headers["X-Generator"])

                # Simple HTML parsing
                soup = BeautifulSoup(response.text, "html.parser")
                generator_tag = soup.find("meta", attrs={"name": "generator"})
                if generator_tag and generator_tag.get("content"):
                    tech_data["technologies"].append(generator_tag["content"])

                # Simple CMS checks
                if "wp-content" in response.text:
                    tech_data["technologies"].append("WordPress")
                if "joomla" in response.text:
                    tech_data["technologies"].append("Joomla")
                if "Drupal" in response.headers.get("X-Generator", ""):
                    tech_data["technologies"].append("Drupal")

                # Remove duplicates
                tech_data["technologies"] = list(set(tech_data["technologies"]))
                
                # Found a working URL, stop checking
                return tech_data
            except httpx.RequestError as e:
                tech_data["error"] = f"Error checking {url}: {e}"
                if verbose:
                    console.print(f"[dim]Tech detection failed for {url}: {e}[/dim]")
            except Exception as e:
                # --- THIS LINE IS UPDATED (Typo fixed) ---
                tech_data["error"] = f"Unexpected error checking {url}: {e}"
                if verbose:
                    console.print(f"[dim]Tech detection failed for {url}: {e}")
    
    return tech_data

async def osint_enrichment(domain: str, timeout: int, verbose: bool) -> Dict[str, Any]:
    """Enriches data with passive DNS and other OSINT sources (e.g., AlienVault OTX)."""
    osint_data = {"subdomains": [], "passive_dns": []}
    
    # Example: Query AlienVault OTX for passive DNS
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"Accept": "application/json"}
    
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)
            
        if response.status_code == 200:
            data = response.json()
            passive_dns = data.get("passive_dns", [])
            seen_ips = set()
            for record in passive_dns:
                if record.get("address") not in seen_ips:
                    osint_data["passive_dns"].append({
                        "ip": record["address"],
                        "hostname": record["hostname"],
                        "last_seen": record["last"],
                    })
                    seen_ips.add(record["address"])
                    
            # Also extract subdomains from hostnames
            subdomains = {record["hostname"] for record in passive_dns if record["hostname"].endswith(f".{domain}")}
            osint_data["subdomains"] = list(subdomains)
        else:
            osint_data["error"] = f"OTX query failed (Status: {response.status_code})"
    except httpx.RequestError as e:
        osint_data["error"] = f"OTX query failed: {e}"
        if verbose:
            console.print(f"Error during OSINT enrichment: {e}")
    
    return osint_data