#!/usr/bin/env python3
"""
Zone-Poker - SMTP Analysis Module
"""
import asyncio
import ssl
import socket
from typing import Dict, Any

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

    sorted_mx = sorted(mx_records, key=lambda r: r.get('priority', 99))

    async def analyze_server(record: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        server = record.get("value")
        if not server:
            return "invalid_record", {"error": "MX record has no value."}

        server_results = {}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server, 25), timeout=timeout
            )

            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            server_results['banner'] = banner.decode('utf-8', 'ignore').strip()

            writer.write(f"EHLO {domain}\r\n".encode())
            await writer.drain()
            ehlo_resp = await asyncio.wait_for(reader.read(4096), timeout=timeout)

            if b'250-STARTTLS' in ehlo_resp:
                server_results['starttls'] = 'Supported'
                writer.write(b"STARTTLS\r\n")
                await writer.drain()
                await asyncio.wait_for(reader.read(1024), timeout=timeout)

                # Upgrade the connection
                ssl_context = ssl.create_default_context()
                # Create a new SSL-wrapped connection over the existing socket
                new_reader, new_writer = await asyncio.open_connection(
                    sock=writer.get_extra_info('socket'),
                    ssl=ssl_context,
                    server_hostname=server
                )

                # Get the certificate from the new secure writer
                cert = new_writer.get_extra_info('ssl_object').getpeercert()
                cert_info = {
                    'subject': dict(x[0] for x in cert.get('subject', [])).get('commonName', 'N/A'),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])).get('commonName', 'N/A'),
                    'valid_from': ssl.cert_time_to_seconds(cert.get('notBefore')),
                    'valid_until': ssl.cert_time_to_seconds(cert.get('notAfter')),
                }
                server_results['certificate'] = cert_info
                new_writer.close()
                await new_writer.wait_closed()
            else:
                server_results['starttls'] = 'Not Supported'
                writer.close()
                await writer.wait_closed()

        except (asyncio.TimeoutError, socket.timeout):
            server_results['error'] = f"Connection timed out after {timeout} seconds."
        except (ConnectionRefusedError, OSError) as e:
            server_results['error'] = f"Could not connect to {server}:25: {e}"
        except Exception as e:
            server_results['error'] = f"An unexpected error occurred: {e}"

        return server, server_results

    tasks = [analyze_server(record) for record in sorted_mx]
    results = await asyncio.gather(*tasks)
    return {server: data for server, data in results if server}