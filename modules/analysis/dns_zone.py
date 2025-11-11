#!/usr/bin/env python3
import asyncio
import dns.resolver
import dns.query
import dns.zone
import dns.exception
import dns.asyncquery
from typing import Dict, List, Any
from ..config import console
from ..utils import _get_resolver

async def attempt_axfr(domain: str, records: Dict[str, List[Dict[str, Any]]], timeout: int, verbose: bool) -> Dict[str, Any]:
    """
    Attempts a zone transfer (AXFR) against all authoritative nameservers.
    Checks both A and AAAA records for nameservers.
    """
    resolver = _get_resolver(timeout)
    axfr_results = {"status": "Not Attempted", "servers": {}}
    ns_records = records.get("NS", [])
    if not ns_records:
        axfr_results["status"] = "Skipped (No NS records found)"
        return axfr_results

    nameservers = [record["value"] for record in ns_records]
    axfr_results["status"] = "Completed"
    
    async def try_axfr(ns):
        ns_ips = []
        try:
            a_answers = await asyncio.to_thread(resolver.resolve, ns, "A")
            ns_ips.extend([str(a) for a in a_answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass 
        
        try:
            aaaa_answers = await asyncio.to_thread(resolver.resolve, ns, "AAAA")
            ns_ips.extend([str(a) for a in aaaa_answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass 
            
        if not ns_ips:
            axfr_results["servers"][ns] = {"status": "Failed (No A/AAAA record for NS)"}
            return

        for ns_ip in ns_ips:
            try:
                zone = await dns.zone.from_xfr(await dns.asyncquery.xfr(ns_ip, domain, timeout=timeout))
                
                nodes = zone.nodes.keys()
                axfr_results["servers"][ns] = {
                    "status": "Successful",
                    "ip_used": ns_ip,
                    "record_count": len(nodes),
                    "records": [str(n) for n in nodes]
                }
                return 
            except dns.exception.FormError:
                axfr_results["servers"][ns] = {"status": "Failed (Refused)", "ip_tried": ns_ip}
            except (dns.exception.Timeout, asyncio.TimeoutError):
                axfr_results["servers"][ns] = {"status": "Failed (Timeout)", "ip_tried": ns_ip}
            except Exception as e:
                axfr_results["servers"][ns] = {"status": f"Failed ({type(e).__name__})", "ip_tried": ns_ip}
                if verbose:
                    console.print(f"AXFR error for {ns} at {ns_ip}: {e}")

    for ns in nameservers:
        await try_axfr(ns)
    
    if any(s.get("status") == "Successful" for s in axfr_results["servers"].values()):
        axfr_results["summary"] = "Vulnerable (Zone Transfer Successful)"
    else:
        axfr_results["summary"] = "Secure (No successful transfers)"
        
    return axfr_results