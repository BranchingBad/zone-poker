#!/usr/bin/env python3
import asyncio
import dns.resolver
import dns.query
import dns.zone
import dns.exception

# import dns.asyncquery # No longer needed
import logging
from typing import Dict, List, Any

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
                # A FormError (e.g., "Refused") is a definitive failure for this IP.
                # We record it but continue to try other IPs for the same NS.
                failure_status = {
                    "status": "Failed (Refused or Protocol Error)",
                    "ip_tried": ns_ip,
                }
                if verbose:
                    logger.debug(f"AXFR FormError for {ns} at {ns_ip}: {e}")
            except (dns.exception.Timeout, asyncio.TimeoutError):
                failure_status = {"status": "Failed (Timeout)", "ip_tried": ns_ip}
            except Exception as e:
                failure_status = {
                    "status": "Failed (ValueError)",
                    "ip_tried": ns_ip,
                }
                if verbose:
                    logger.debug(f"AXFR error for {ns} at {ns_ip}: {e}")

            # If the loop completes without returning on success, it means all IPs failed.
            # We record the last known failure for this nameserver.
            async with lock:
                axfr_results["servers"][ns] = failure_status

    tasks = [try_axfr(ns) for ns in nameservers]
    await asyncio.gather(*tasks)

    if any(s.get("status") == "Successful" for s in axfr_results["servers"].values()):
        axfr_results["summary"] = "Vulnerable (Zone Transfer Successful)"
    else:
        axfr_results["summary"] = "Secure (No successful transfers)"

    return axfr_results
