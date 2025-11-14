#!/usr/bin/env python3
"""
Zone-Poker - SMTP Analysis Module
"""

import asyncio
import smtplib
import socket
import ssl
from typing import Any, Dict


async def analyze_smtp_servers(domain: str, timeout: int, records_info: dict, **kwargs) -> dict:
    """
    Asynchronously connects to mail servers from MX records to analyze their SMTP configuration.
    Args:
        records_info: The dictionary of DNS records from the 'records' module.
        domain: The target domain, used for the EHLO command.
        timeout: Connection timeout in seconds.

    Returns:
        A dictionary containing analysis results for each mail server.
    """
    mx_records = records_info.get("MX", [])
    if not mx_records:
        return {"error": "No MX records found to analyze."}

    sorted_mx = sorted(mx_records, key=lambda r: r.get("priority", 99))

    def run_sync_analysis(record: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        """Synchronous function to be run in a thread."""
        server_name = record.get("value")
        if not server_name:
            return "invalid_record", {"error": "MX record has no value"}

        server_results = {}
        try:
            with smtplib.SMTP(server_name, port=25, timeout=timeout) as smtp:
                # Send EHLO to discover server capabilities like STARTTLS
                smtp.ehlo()
                server_results["banner"] = smtp.helo_resp.decode("utf-8", "ignore").strip() if smtp.helo_resp else "N/A"
                if smtp.has_extn("starttls"):
                    server_results["starttls"] = "Supported"
                    smtp.starttls()
                    # We must call ehlo() again after STARTTLS
                    smtp.ehlo()
                    cert = smtp.sock.getpeercert()
                    if cert:
                        cert_info = {
                            "subject": dict(x[0] for x in cert.get("subject", [])).get("commonName", "N/A"),
                            "issuer": dict(x[0] for x in cert.get("issuer", [])).get("commonName", "N/A"),
                            "valid_from": ssl.cert_time_to_seconds(cert.get("notBefore")),
                            "valid_until": ssl.cert_time_to_seconds(cert.get("notAfter")),
                        }
                        server_results["certificate"] = cert_info
                else:
                    server_results["starttls"] = "Not Supported"
        except smtplib.SMTPHeloError as e:
            server_results["error"] = f"Server didn't reply properly to EHLO: {e}"
        except socket.timeout:
            server_results["error"] = f"Connection timed out after {timeout} seconds."
        except (ConnectionRefusedError, OSError) as e:
            server_results["error"] = f"Could not connect to {server_name}:25: {e}"
        except Exception as e:
            server_results["error"] = f"An unexpected error occurred: {e}"

        return server_name, server_results

    # Wrap the synchronous function call in asyncio.to_thread
    tasks = [asyncio.to_thread(run_sync_analysis, record) for record in sorted_mx]
    results = await asyncio.gather(*tasks)
    return {server: data for server, data in results if server}
