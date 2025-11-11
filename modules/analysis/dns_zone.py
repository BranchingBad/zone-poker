#!/usr/bin/env python3
import asyncio
import dns.resolver
import dns.query
import dns.zone
import dns.exception
# import dns.asyncquery # No longer needed
from typing import Dict, List, Any, Optional
from ..config import console

async def attempt_axfr(domain: str, records: Dict[str, List[Dict[str, Any]]], resolver: dns.resolver.Resolver, timeout: int, verbose: bool, **kwargs) -> Dict[str, Any]:
    """
    Attempts a zone transfer (AXFR) against all authoritative nameservers.
    Checks both A and AAAA records for nameservers.
    """
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
            ns_ips.extend([str(a) for a in a_answers]) # type: ignore
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            pass 
        
        try:
            aaaa_answers = await asyncio.to_thread(resolver.resolve, ns, "AAAA")
            ns_ips.extend([str(a) for a in aaaa_answers]) # type: ignore
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            pass 

        if not ns_ips:
            axfr_results["servers"][ns] = {"status": "Failed (No A/AAAA record for NS)"}
            return

        for ns_ip in ns_ips:
            try:
                # The dns.query.xfr function is blocking and returns a generator.
                # Both the query and the consumption of the generator by dns.zone.from_xfr
                # must occur within the same thread to work correctly with asyncio.
                def _do_xfr():
                    try:
                        xfr_generator = dns.query.xfr(ns_ip, domain, timeout=timeout)
                        return dns.zone.from_xfr(xfr_generator)
                    except dns.exception.FormError:
                        # A FormError during from_xfr often indicates a "Refused" response.
                        return None

                zone = await asyncio.to_thread(_do_xfr)
                
                # If the zone transfer was refused or failed at the protocol level,
                # _do_xfr returns None, which we can use to raise a specific exception.
                if zone is None:
                    raise dns.exception.FormError("Zone is None, likely refused.")

                nodes = zone.nodes.keys() # type: ignore
                axfr_results["servers"][ns] = {
                    "status": "Successful",
                    "ip_used": ns_ip,
                    "record_count": len(nodes),
                    "records": [str(n) for n in nodes]
                }
                return 
            except dns.exception.FormError:
                # A FormError (e.g., "Refused") is a definitive failure for this nameserver.
                axfr_results["servers"][ns] = {"status": "Failed (Refused or Protocol Error)", "ip_tried": ns_ip}
                return
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