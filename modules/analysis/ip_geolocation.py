#!/usr/bin/env python3
"""
Zone-Poker - IP Geolocation Module
"""

import asyncio
import logging
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)
IP_API_BATCH_ENDPOINT = "http://ip-api.com/batch"


async def geolocate_ips(all_data: Dict[str, Any], **kwargs) -> Dict[str, Dict[str, str]]:
    """
    Geolocates IP addresses from A/AAAA records and headers using the ip-api.com batch endpoint.
    """
    records_info = all_data.get("records_info", {})
    headers_info = all_data.get("headers_info", {})
    geo_results: Dict[str, Dict[str, str]] = {}

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

    if not ips_to_check:
        return {}

    # ip-api.com batch endpoint supports up to 100 IPs per request
    BATCH_SIZE = 100
    ip_chunks = [ips_to_check[i : i + BATCH_SIZE] for i in range(0, len(ips_to_check), BATCH_SIZE)]

    async def _geolocate_batch(ip_chunk: List[str], client: httpx.AsyncClient):
        """Inner function to geolocate a batch of IPs."""
        # 'query' is needed to map results back to the IP
        url = f"{IP_API_BATCH_ENDPOINT}?fields=status,message,country,city,isp,query"
        try:
            response = await client.post(url, json=ip_chunk, timeout=10)
            response.raise_for_status()
            batch_data = response.json()

            for data in batch_data:
                ip = data.get("query")
                if not ip:
                    continue

                if data.get("status") == "success":
                    geo_results[ip] = {
                        "isp": data.get("isp", "N/A"),
                        "country": data.get("country", "N/A"),
                        "city": data.get("city", "N/A"),
                    }
                else:
                    geo_results[ip] = {"error": data.get("message", "API error")}
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.warning(f"IP geolocation batch request failed: {e}")
            # Mark all IPs in this failed chunk as errored
            for ip in ip_chunk:
                geo_results[ip] = {"error": f"Batch request failed: {type(e).__name__}"}

    async with httpx.AsyncClient() as client:
        tasks = [_geolocate_batch(chunk, client) for chunk in ip_chunks]
        await asyncio.gather(*tasks)

    return geo_results
