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
from .utils import join_txt_chunks, get_parent_zone

# ... (all helper functions and other analysis functions remain the same) ...
async def get_dns_records(domain: str, timeout: int, verbose: bool): ...
def _format_rdata(rtype: str, rdata: Any, ttl: int): ...
def _parse_spf_record(spf_record: str): ...
async def reverse_ptr_lookups(records: Dict[str, List[Dict[str, Any]]], timeout: int, verbose: bool): ...
def email_security_analysis(domain: str, records: Dict[str, List[Dict[str, Any]]]): ...
async def whois_lookup(domain: str, verbose: bool): ...
async def nameserver_analysis(records: Dict[str, List[Dict[str, Any]]], timeout: int, verbose: bool): ...
async def propagation_check(domain: str, timeout: int): ...
def security_audit(records: Dict[str, List[Dict[str, Any]]], email_security: Dict[str, Any]): ...
async def detect_technologies(domain: str, timeout: int, verbose: bool): ...
async def osint_enrichment(domain: str, timeout: int, verbose: bool): ...


async def attempt_axfr(domain: str, records: Dict[str, List[Dict[str, Any]]], timeout: int, verbose: bool) -> Dict[str, Any]:
    """Attempts a zone transfer (AXFR) against all authoritative nameservers."""
    axfr_results = {"status": "Not Attempted", "servers": {}}
    ns_records = records.get("NS", [])
    if not ns_records:
        axfr_results["status"] = "Skipped (No NS records found)"
        return axfr_results

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
            # --- THIS IS THE CORRECTED LINE ---
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