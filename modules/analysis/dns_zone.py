#!/usr/bin/env python3
import asyncio

# import dns.asyncquery # No longer needed
import logging
from typing import Any, Dict, List

import dns.exception
import dns.query
import dns.resolver
import dns.zone

logger = logging.getLogger(__name__)


async def attempt_axfr(
    domain: str,
    resolver: dns.resolver.Resolver,
    timeout: int,
    verbose: bool,
    records_info: Dict[str, List[Dict[str, Any]]],
    **kwargs,
) -> Dict[str, Any]:
    """
    Attempts a zone transfer (AXFR) against all authoritative nameservers.
    Checks both A and AAAA records for nameservers.
    """
    axfr_results = {"status": "Not Attempted", "servers": {}}
    ns_records = records_info.get("NS", [])
    if not ns_records:
        axfr_results["status"] = "Skipped (No NS records found)"
        return axfr_results

    nameservers = [record["value"] for record in ns_records]
    axfr_results["status"] = "Completed"

    lock = asyncio.Lock()

    async def _resolve_ns_ips(ns: str, rtype: str) -> List[str]:
        """Helper to resolve A or AAAA records for a nameserver."""
        try:
            answers = await asyncio.to_thread(resolver.resolve, ns, rtype)
            return [str(a) for a in answers]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
            dns.resolver.NoNameservers,
        ):
            return []

    async def try_axfr(ns: str):
        # Concurrently resolve A and AAAA records for the nameserver
        a_records, aaaa_records = await asyncio.gather(
            _resolve_ns_ips(ns, "A"), _resolve_ns_ips(ns, "AAAA")
        )
        ns_ips = a_records + aaaa_records

        if not ns_ips:
            # Use a lock to safely write to the shared results dictionary
            async with lock:  # noqa
                axfr_results["servers"][ns] = {
                    "status": "Failed (No A/AAAA record for NS)"
                }
            return

        failure_status = {}  # Initialize failure status for the nameserver
        for ns_ip in ns_ips:
            try:
                # The dns.query.xfr function is blocking and returns a generator.
                # Both the query and the consumption of the generator by dns.zone.from_xfr
                # must occur within the same thread to work correctly with asyncio.
                def _do_xfr_blocking(ns_ip_addr):
                    xfr_generator = dns.query.xfr(ns_ip_addr, domain, timeout=timeout)
                    return dns.zone.from_xfr(xfr_generator)

                # Run the blocking operation in a separate thread
                zone = await asyncio.to_thread(_do_xfr_blocking, ns_ip)

                nodes = zone.nodes.keys()  # type: ignore
                async with lock:  # noqa
                    axfr_results["servers"][ns] = {
                        "status": "Successful",
                        "ip_used": ns_ip,
                        "record_count": len(nodes),
                        "records": [str(n) for n in nodes],
                    }
                return  # Success, no need to check other IPs for this NS
            except dns.exception.FormError as e:
                # A "Refused" error is definitive for this IP. Stop trying other IPs for this NS.
                status_msg = (
                    "Failed (Refused)"
                    if "refused" in str(e).lower()
                    else "Failed (Protocol Error)"
                )
                failure_status = {"status": status_msg, "ip_tried": ns_ip}
                if verbose:
                    logger.debug(f"AXFR FormError for {ns} at {ns_ip}: {e}")
                break  # A refusal is definitive, no need to check other IPs.
            except dns.exception.Timeout:  # Removed redundant asyncio.TimeoutError
                # Only update if we don't already have a more specific error.
                if not failure_status:
                    failure_status = {"status": "Failed (Timeout)", "ip_tried": ns_ip}
                if verbose:
                    logger.debug(f"AXFR timeout for {ns} at {ns_ip}")
            except Exception as e:
                # Only record a generic exception if no other failure has been recorded yet.
                # This prevents overwriting a more specific error like a Timeout.
                if not failure_status or "Failed (" not in failure_status.get(
                    "status", ""
                ):
                    failure_status = {
                        "status": f"Failed ({type(e).__name__})",
                        "ip_tried": ns_ip,
                    }
                if verbose:
                    logger.debug(f"AXFR error for {ns} at {ns_ip}: {e}")

        # After trying all IPs for the nameserver, if a failure occurred, record it.
        if failure_status:
            async with lock:
                axfr_results["servers"][ns] = failure_status

    tasks = [try_axfr(ns) for ns in nameservers]

    # Wait for all tasks to complete.
    await asyncio.gather(*tasks)

    # After all tasks are done, check the results.
    if any(s.get("status") == "Successful" for s in axfr_results["servers"].values()):
        axfr_results["summary"] = "Vulnerable (Zone Transfer Successful)"
    else:
        axfr_results["summary"] = "Secure (No successful transfers)"

    return axfr_results
