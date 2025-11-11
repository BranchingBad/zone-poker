#!/usr/bin/env python3
"""
Zone-Poker - Domain & IP Reputation Analysis Module
"""
import httpx
from typing import Dict, List, Any
import argparse # Added import

ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

def analyze_reputation(domain: str, args: argparse.Namespace, records: dict, **kwargs) -> dict:
    """
    Checks the reputation of domain IPs against AbuseIPDB.

    Args:
        domain: The target domain (unused in this implementation but good practice).
        records: The dictionary of DNS records from the 'records' module.
        args: The application's arguments namespace, used for API keys and timeout.

    Returns:
        A dictionary containing reputation details for each IP.
    """
    api_key = getattr(args, 'api_keys', {}).get("abuseipdb")
    if not api_key:
        return {"error": "AbuseIPDB API key not found in config file."}

    # Consolidate all A and AAAA records
    ip_addresses = []
    for record_type in ["A", "AAAA"]:
        ip_addresses.extend([rec.get("value") for rec in records.get(record_type, []) if rec.get("value")])

    if not ip_addresses:
        return {"error": "No A or AAAA records found to check reputation."}

    results = {}
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    # Use httpx for async requests in the future if needed, but for simplicity,
    # we'll use synchronous requests here. httpx is a good choice as it supports both.
    with httpx.Client(timeout=args.timeout) as client:
        for ip in set(ip_addresses): # Use set to avoid duplicate checks
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }
            try:
                response = client.get(ABUSEIPDB_ENDPOINT, headers=headers, params=params)
                response.raise_for_status()  # Raise an exception for 4xx/5xx responses
                
                data = response.json().get('data', {})
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

    return results