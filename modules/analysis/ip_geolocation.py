#!/usr/bin/env python3
"""
Zone-Poker - IP Geolocation Analysis Module
"""
import httpx
import asyncio
import logging
from typing import Dict, Any, List, Set

logger = logging.getLogger(__name__)

async def geolocate_ips(records: Dict[str, List[Dict[str, Any]]], **kwargs) -> Dict[str, Dict[str, Any]]:
    """
    Performs IP geolocation for discovered A and AAAA records using ip-api.com.
    """
    results: Dict[str, Dict] = {}
    ips_to_check: Set[str] = set()

    # Flatten all A and AAAA records into a set of unique IPs
    for r_type in ["A", "AAAA"]:
        for record in records.get(r_type, []):
            if record.get("value"):
                ips_to_check.add(record["value"])

    if not ips_to_check:
        return {}

    logger.debug(f"Geolocating {len(ips_to_check)} unique IP addresses.")
    async with httpx.AsyncClient() as client:
        tasks = {ip: client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp", timeout=10) for ip in ips_to_check}
        responses = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for (ip, _), response in zip(tasks.items(), responses):
            if isinstance(response, Exception):
                results[ip] = {"error": f"Request failed: {type(response).__name__}"}
                continue

            try:
                data = response.json()
                if data.get("status") == "success":
                    results[ip] = {k: v for k, v in data.items() if k != "status"}
                else:
                    results[ip] = {"error": data.get("message", "Failed to geolocate")}
            except Exception as e:
                results[ip] = {"error": f"Failed to parse response: {e}"}

    return results