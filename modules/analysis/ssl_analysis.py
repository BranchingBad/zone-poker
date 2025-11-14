#!/usr/bin/env python3
"""
Zone-Poker - SSL/TLS Analysis Module
"""
import asyncio
import socket
import ssl
from urllib.parse import urlparse


async def analyze_ssl_certificate(
    domain: str, timeout: int, all_data: dict, **kwargs
) -> dict:
    """
    Connects to a domain over HTTPS to retrieve and analyze its SSL/TLS certificate.
    It will prioritize the final redirected URL from the http_headers module if available.

    Args:
        domain: The domain to check.
        timeout: Connection timeout in seconds.
        all_data: The dictionary containing all collected data.

    Returns:
        A dictionary containing certificate details or an error message.
    """
    # Use the final URL from the headers check if available, otherwise default to the original domain.
    headers_info = all_data.get("headers_info", {})
    final_url = headers_info.get("final_url")

    hostname = urlparse(final_url).hostname if final_url else domain
    port = 443
    results = {}

    try:
        context = ssl.create_default_context()
        # The ssl parameter should be the context object, not just True.
        # This ensures asyncio manages the SSL transport layer correctly,
        # preventing the resource warning on exit.
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                hostname, port, ssl=context, server_hostname=hostname
            ),
            timeout=timeout,
        )
        try:
            # Directly use the dictionary returned by getpeercert().
            if cert := writer.get_extra_info("peercert"):
                results["status"] = "Success"
                results["tls_version"] = writer.get_extra_info("ssl_object").version()
                results["cipher"] = writer.get_extra_info("ssl_object").cipher()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                results["subject"] = subject.get("commonName", "N/A")
                results["issuer"] = issuer.get("commonName", "N/A")
                if not_before := cert.get("notBefore"):
                    results["valid_from"] = ssl.cert_time_to_seconds(not_before)
                if not_after := cert.get("notAfter"):
                    results["valid_until"] = ssl.cert_time_to_seconds(not_after)
                if subject_alt_name := cert.get("subjectAltName"):
                    results["sans"] = [value for _, value in subject_alt_name]
        finally:
            writer.close()
            await writer.wait_closed()

    except ssl.SSLCertVerificationError as e:
        results["error"] = f"Certificate verification failed: {e.reason}"
    except (socket.timeout, asyncio.TimeoutError):
        results["error"] = f"Connection timed out after {timeout} seconds."
    except (ConnectionRefusedError, socket.gaierror, OSError) as e:
        results["error"] = f"Could not connect to {hostname} on port {port}: {e}"
    except Exception as e:
        results["error"] = f"An unexpected error occurred: {e}"

    return results
