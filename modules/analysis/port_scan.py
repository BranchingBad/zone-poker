#!/usr/bin/env python3
"""
Zone-Poker - Port Scan Module
"""
import asyncio
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# A list of common TCP ports to check. This list is a balance between
# being comprehensive and keeping scan times reasonable.
COMMON_PORTS = [
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    465,
    587,
    993,
    995,
    2078,
    2082,
    2083,
    2086,
    2087,
    2095,
    2096,
    3306,
    5432,
    8080,
    8443,
]


async def scan_ports(
    all_data: Dict[str, Any], timeout: int, verbose: bool, **kwargs
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Scans for common open TCP ports on discovered IP addresses.
    """
    records_info = all_data.get("records_info", {}) or {}
    headers_info = all_data.get("headers_info", {})
    scan_results: List[Dict[str, Any]] = []

    ips_to_check: List[str] = []
    for r_type in ("A", "AAAA"):
        for record in records_info.get(r_type, []):
            if record.get("value"):
                ips_to_check.append(record["value"])

    # Also check the IP from the final URL in http_headers if available
    if headers_info and headers_info.get("ip_address"):
        ips_to_check.append(headers_info["ip_address"])

    # Remove duplicates
    ips_to_check = sorted(list(set(ips_to_check)))

    async def _scan_ip(ip: str):
        """Scans a single IP for open ports."""
        open_ports = []
        tasks = [_check_port(ip, port, timeout) for port in COMMON_PORTS]
        results = await asyncio.gather(*tasks)
        for port, is_open in results:
            if is_open:
                open_ports.append(port)

        if open_ports:
            scan_results.append({"ip": ip, "ports": sorted(open_ports)})

    async def _check_port(ip: str, port: int, conn_timeout: int):
        """Checks if a single port is open."""
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=conn_timeout)
            writer.close()
            await writer.wait_closed()
            return port, True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return port, False
        except Exception as e:
            if verbose:
                logger.warning(f"Port scan error on {ip}:{port}: {e}")
            return port, False

    scan_tasks = [_scan_ip(ip) for ip in ips_to_check]
    await asyncio.gather(*scan_tasks)

    return {"scan_results": scan_results}
