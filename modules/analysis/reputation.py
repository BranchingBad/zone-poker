#!/usr/bin/env python3
"""
Zone-Poker - Domain & IP Reputation Analysis Module
"""

import argparse
import asyncio

import httpx

ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"


async def analyze_reputation(domain: str, args: argparse.Namespace, all_data: dict, **kwargs) -> dict:
    """
    Checks the reputation of domain IPs against AbuseIPDB.

    Args:
        domain: The target domain (unused in this implementation but good practice).
        records_info: The dictionary of DNS records from the 'records' module.
        all_data: The dictionary containing all collected data.

    Returns:
        A dictionary containing reputation details for each IP.
    """
    api_key = getattr(args, "api_keys", {}).get("abuseipdb")
    if not api_key:
        return {"error": "AbuseIPDB API key not found in config file."}

    records_info = all_data.get("records_info", {})
    headers_info = all_data.get("headers_info", {})

    # Consolidate all A and AAAA records
    ip_addresses = []
    for record_type in ("A", "AAAA"):
        if record_list := records_info.get(record_type):
            ip_addresses.extend(rec.get("value") for rec in record_list if rec.get("value"))

    if headers_info and headers_info.get("ip_address"):
        ip_addresses.append(headers_info["ip_address"])

    if not ip_addresses:
        return {"error": "No A or AAAA records found to check reputation."}

    results = {}
    headers = {"Accept": "application/json", "Key": api_key}

    async def check_ip(ip: str, client: httpx.AsyncClient) -> None:
        """Inner function to check a single IP."""
        try:
            params = {"ipAddress": ip, "maxAgeInDays": "90"}
            response = await client.get(ABUSEIPDB_ENDPOINT, headers=headers, params=params)
            response.raise_for_status()  # Raise an exception for 4xx/5xx responses

            data = response.json().get("data", {})
            results[ip] = {
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "countryCode": data.get("countryCode"),
                "usageType": data.get("usageType"),
                "isp": data.get("isp"),
                "totalReports": data.get("totalReports"),
                "lastReportedAt": data.get("lastReportedAt"),
            }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                results[ip] = {"error": "Authentication failed (invalid API key)."}
            else:
                results[ip] = {"error": f"HTTP error {e.response.status_code}: {e.response.text}"}
        except httpx.RequestError as e:
            results[ip] = {"error": f"Connection error: {e}"}

    async with httpx.AsyncClient(timeout=args.timeout) as client:
        tasks = [check_ip(ip, client) for ip in set(ip_addresses)]
        await asyncio.gather(*tasks)

    return results
