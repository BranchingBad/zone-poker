#!/usr/bin/env python3
"""
Zone-Poker - SMTP Analysis Module
"""
import smtplib
import ssl
import socket

def analyze_smtp_servers(domain: str, timeout: int, records_info: dict, **kwargs) -> dict:
    """
    Connects to mail servers from MX records to analyze their SMTP configuration.

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

    results = {}
    sorted_mx = sorted(mx_records, key=lambda r: r.get('priority', 99))

    for record in sorted_mx:
        server = record.get("value")
        if not server:
            continue

        server_results = {}
        try:
            with smtplib.SMTP(server, port=25, timeout=timeout) as smtp:
                server_results['banner'] = smtp.helo_resp.decode('utf-8', 'ignore').strip() if smtp.helo_resp else "N/A"
                
                if smtp.has_extn('starttls'):
                    server_results['starttls'] = 'Supported'
                    smtp.starttls()
                    
                    cert = smtp.sock.getpeercert()
                    cert_info = {}
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    cert_info['subject'] = subject.get('commonName', 'N/A')
                    cert_info['issuer'] = issuer.get('commonName', 'N/A')
                    
                    cert_info['valid_from'] = ssl.cert_time_to_seconds(cert.get('notBefore'))
                    cert_info['valid_until'] = ssl.cert_time_to_seconds(cert.get('notAfter'))
                    
                    server_results['certificate'] = cert_info
                else:
                    server_results['starttls'] = 'Not Supported'

        except smtplib.SMTPHeloError as e:
            server_results['error'] = f"Server didn't reply properly to EHLO: {e}"
        except socket.timeout:
            server_results['error'] = f"Connection timed out after {timeout} seconds."
        except (ConnectionRefusedError, OSError) as e:
            server_results['error'] = f"Could not connect to {server}:25: {e}"
        except Exception as e:
            server_results['error'] = f"An unexpected error occurred: {e}"
        
        results[server] = server_results

    return results