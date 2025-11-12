#!/usr/bin/env python3
"""
Zone-Poker - SSL/TLS Analysis Module
"""
import ssl
import socket


def analyze_ssl_certificate(domain: str, timeout: int, **kwargs) -> dict:
    """
    Connects to a domain over HTTPS to retrieve and analyze its SSL/TLS certificate.

    Args:
        domain: The domain to check.
        timeout: Connection timeout in seconds.

    Returns:
        A dictionary containing certificate details or an error message.
    """
    hostname = domain
    port = 443
    results = {}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                results["status"] = "Success"
                results["tls_version"] = ssock.version()
                results["cipher"] = ssock.cipher()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                results["subject"] = subject.get("commonName", "N/A")
                results["issuer"] = issuer.get("commonName", "N/A")
                results["valid_from"] = ssl.cert_time_to_seconds(cert.get("notBefore"))
                results["valid_until"] = ssl.cert_time_to_seconds(cert.get("notAfter"))
                results["sans"] = [
                    value for type, value in cert.get("subjectAltName", [])
                ]

    except ssl.SSLCertVerificationError as e:
        results["error"] = f"Certificate verification failed: {e.reason}"
    except socket.timeout:
        results["error"] = f"Connection timed out after {timeout} seconds."
    except (ConnectionRefusedError, socket.gaierror, OSError) as e:
        results["error"] = f"Could not connect to {hostname} on port {port}: {e}"
    except Exception as e:
        results["error"] = f"An unexpected error occurred: {e}"

    return results


# [FIX] The extra '}' at the end of the file has been removed.
