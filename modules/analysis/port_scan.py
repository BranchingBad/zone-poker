#!/usr/bin/env python3
"""
Zone-Poker - Open Port Scanning Module
"""
import asyncio
import logging
from typing import Dict, List, Set, Any

logger = logging.getLogger(__name__)

# A list of common ports to check
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5900, 8080, 8443]

async def scan_ports(records: Dict[str, List[Dict[str, Any]]], **kwargs) -> Dict[str, Any]:
    """
    Scans for common open TCP ports on discovered IP addresses.
    """
    results: Dict[str, List[int]] = {}
    ips_to_check: Set[str] = {
        rec["value"] for rec_type in ["A", "AAAA"] for rec in records.get(rec_type, []) if rec.get("value")
    }

    if not ips_to_check:
        return {}

    logger.debug(f"Scanning {len(COMMON_PORTS)} common ports on {len(ips_to_check)} unique IP addresses.")

    async def check_port(ip: str, port: int):
        try:
            # Set a short timeout for the connection attempt
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            return ip, port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None  # Port is closed or unreachable
        except Exception as e:
            logger.debug(f"Error scanning port {port} on {ip}: {e}")
            return None

    tasks = [check_port(ip, port) for ip in ips_to_check for port in COMMON_PORTS]
    scan_results = await asyncio.gather(*tasks)

    for result in filter(None, scan_results):
        ip, port = result
        results.setdefault(ip, []).append(port)

    # Sort ports for consistent output
    for ip in results:
        results[ip].sort()

    return results