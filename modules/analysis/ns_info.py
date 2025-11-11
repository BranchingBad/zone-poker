#!/usr/bin/env python3
import asyncio
import dns.resolver
from typing import Dict, List, Any
from ipwhois import IPWhois
from ..config import console
from ..utils import _get_resolver

async def nameserver_analysis(records: Dict[str, List[Dict[str, Any]]], timeout: int, verbose: bool) -> Dict[str, Any]:
    """Analyzes nameservers, checking IPs (A and AAAA) and DNSSEC support."""
    resolver = _get_resolver(timeout)
    ns_info = {}
    ns_records = records.get("NS", [])
    if not ns_records:
        return {"error": "No NS records found."}

    
    async def analyze_ns(ns_record):
        ns_name = ns_record["value"]
        info = {"ips": []}
        ns_ips = []
        try:
            a_answers = await asyncio.to_thread(resolver.resolve, ns_name, "A")
            ns_ips.extend([str(a) for a in a_answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass 
        
        try:
            aaaa_answers = await asyncio.to_thread(resolver.resolve, ns_name, "AAAA")
            ns_ips.extend([str(a) for a in aaaa_answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass 

        if not ns_ips:
            info["error"] = "No A or AAAA records found for NS"
            ns_info[ns_name] = info
            return

        first_ip = ns_ips[0]
        info["ips"] = ns_ips
        
        try:
            obj = IPWhois(first_ip)
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

    for ns in ns_records:
        await analyze_ns(ns)
    
    # Check DNSSEC
    if records.get("DNSKEY") and records.get("DS"):
        ns_info["dnssec"] = "Enabled (DNSKEY and DS records found)"
    elif records.get("DNSKEY"):
        ns_info["dnssec"] = "Partial (DNSKEY found, but no DS record)"
    else:
        ns_info["dnssec"] = "Not Enabled (No DNSKEY or DS records)"
        
    return ns_info