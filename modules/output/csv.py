#!/usr/bin/env python3
"""
Zone-Poker - CSV Output Module
Handles the generation of a comprehensive CSV report for DNS records.
"""

import builtins
import csv
import datetime
import io
from typing import Any, Dict, List, Optional, Set

from ..config import console
from ..dispatch_table import MODULE_DISPATCH_TABLE


def _write_dns_records_to_csv(writer: csv.writer, domain: str, timestamp: str, records_info: Dict[str, Any]):
    """
    Writes DNS records to the provided CSV writer.
    """
    if not records_info or not isinstance(records_info, dict):
        return

    # --- THIS BLOCK IS REFACTORED ---
    # 1. Dynamically determine all possible headers from the records data.
    all_headers: Set[str] = set()
    all_records: List[Dict[str, Any]] = []
    if isinstance(records_info, dict):
        for r_type, records in records_info.items():
            for record in records:
                record["record_type"] = r_type  # Add record type to the dict
                all_headers.update(record.keys())
                all_records.append(record)

    # 2. Create a sorted, consistent header row.
    # These are placed first for better readability.
    base_headers = ["domain", "scan_timestamp", "record_type", "name", "value", "ttl"]
    extra_headers = sorted([h for h in all_headers if h not in base_headers])
    final_headers = base_headers + extra_headers
    writer.writerow(final_headers)

    # 3. Write each record to the CSV.
    for record in all_records:
        row = [domain, timestamp] + [record.get(h, "") for h in final_headers[2:]]
        writer.writerow(row)


def _write_whois_to_csv(writer: csv.writer, whois_info: Dict[str, Any]):
    """
    Writes WHOIS information to the provided CSV writer.
    """

    # Create headers from the keys of the WHOIS data
    headers = sorted(whois_info.keys())
    writer.writerow(headers)

    # Write the single row of WHOIS data
    row = [whois_info.get(h, "") for h in headers]
    writer.writerow(row)


def _write_mail_info_to_csv(writer: csv.writer, mail_info: Dict[str, Any]):
    """
    Writes Email Security (SPF, DMARC) information to the provided CSV writer.
    """

    headers = ["check_type", "attribute", "value"]
    writer.writerow(headers)

    for check_type, details in mail_info.items():
        if isinstance(details, dict):
            for attribute, value in details.items():
                writer.writerow([check_type, attribute, value])
        else:
            writer.writerow([check_type, "status", details])


def _write_http_headers_to_csv(writer: csv.writer, headers_info: Dict[str, Any]):
    """
    Writes HTTP Security Headers analysis to the provided CSV writer.
    """

    # Write final URL
    writer.writerow(["attribute", "value"])
    writer.writerow(["final_url", headers_info.get("final_url", "N/A")])
    writer.writerow([])  # Blank line

    # Write header analysis
    writer.writerow(["Header Analysis"])
    writer.writerow(["header", "status", "value"])
    for header, details in headers_info.get("analysis", {}).items():
        if isinstance(details, dict):
            writer.writerow([header, details.get("status", ""), details.get("value", "")])
    writer.writerow([])  # Blank line

    # Write recommendations
    if recommendations := headers_info.get("recommendations", []):
        writer.writerow(["Recommendations"])
        for rec in recommendations:
            writer.writerow([rec])


def _write_security_audit_to_csv(writer: csv.writer, security_info: Dict[str, Any]):
    """
    Writes Security Audit findings to the provided CSV writer.
    """

    findings = security_info.get("findings", [])
    if not findings:
        writer.writerow(["All security checks passed."])
        return

    headers = ["severity", "finding", "recommendation"]
    writer.writerow(headers)

    for finding in findings:
        writer.writerow([finding.get(h, "") for h in headers])


def _write_ssl_info_to_csv(writer: csv.writer, ssl_info: Dict[str, Any]):
    """
    Writes SSL/TLS Certificate analysis to the provided CSV writer.
    """

    # Write main certificate details
    writer.writerow(["attribute", "value"])
    writer.writerow(["subject", ssl_info.get("subject", "N/A")])
    writer.writerow(["issuer", ssl_info.get("issuer", "N/A")])

    if valid_from_ts := ssl_info.get("valid_from"):
        valid_from_dt = datetime.datetime.fromtimestamp(valid_from_ts).strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow(["valid_from", valid_from_dt])

    if valid_until_ts := ssl_info.get("valid_until"):
        valid_until_dt = datetime.datetime.fromtimestamp(valid_until_ts).strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow(["valid_until", valid_until_dt])

    writer.writerow(["tls_version", ssl_info.get("tls_version", "N/A")])
    writer.writerow([])  # Blank line

    # Write Subject Alternative Names (SANs)
    if sans := ssl_info.get("sans", []):
        writer.writerow(["Subject Alternative Names (SANs)"])
        for san in sans:
            writer.writerow([san])


def _write_geolocation_to_csv(writer: csv.writer, geo_info: Dict[str, Any]):
    """
    Writes IP Geolocation analysis to the provided CSV writer.
    """

    headers = ["ip_address", "country", "city", "isp", "error"]
    writer.writerow(headers)

    # The geo_info data is a dictionary where keys are IP addresses.
    for ip, details in geo_info.items():
        if isinstance(details, dict):
            writer.writerow(
                [
                    ip,
                    details.get("country", ""),
                    details.get("city", ""),
                    details.get("isp", ""),
                ]
            )


def _write_port_scan_to_csv(writer: csv.writer, port_scan_info: Dict[str, Any]):
    """
    Writes Open Port Scan results to the provided CSV writer.
    """

    headers = ["ip_address", "open_ports"]
    writer.writerow(headers)

    # The port_scan_info data is a list of dictionaries.
    for item in port_scan_info:
        if isinstance(item, dict):
            ip = item.get("ip", "N/A")
            ports_str = ", ".join(map(str, item.get("ports", [])))
            writer.writerow([ip, ports_str])


def _write_subdomain_takeover_to_csv(writer: csv.writer, takeover_info: Dict[str, Any]):
    """
    Writes Subdomain Takeover results to the provided CSV writer.
    """

    vulnerable = takeover_info.get("vulnerable", [])
    if not vulnerable:
        writer.writerow(["No potential subdomain takeovers found."])
        return

    headers = ["subdomain", "service", "cname_target"]
    writer.writerow(headers)

    for item in vulnerable:
        writer.writerow([item.get(h, "") for h in headers])


def _write_dnsbl_to_csv(writer: csv.writer, dnsbl_info: Dict[str, Any]):
    """
    Writes DNS Blocklist (DNSBL) check results to the provided CSV writer.
    """

    listed_ips = dnsbl_info.get("listed_ips", [])
    if not listed_ips:
        writer.writerow(["No discovered IPs were found on common DNS blocklists."])
        return

    headers = ["ip_address", "listed_on"]
    writer.writerow(headers)

    for item in listed_ips:
        listed_on_str = ", ".join(item.get("listed_on", []))
        writer.writerow([item.get("ip", ""), listed_on_str])


def _write_cloud_enum_to_csv(writer: csv.writer, cloud_info: Dict[str, Any]):
    """
    Writes Cloud Enumeration results to the provided CSV writer.
    """
    s3_buckets = cloud_info.get("s3_buckets", [])
    azure_blobs = cloud_info.get("azure_blobs", [])

    if not s3_buckets and not azure_blobs:
        writer.writerow(["No public S3 or Azure Blob containers found."])
        return

    headers = ["service_type", "url", "status"]
    writer.writerow(headers)

    for bucket in s3_buckets:
        writer.writerow(["s3_bucket", bucket.get("url", ""), bucket.get("status", "")])

    for blob in azure_blobs:
        writer.writerow(["azure_blob", blob.get("url", ""), blob.get("status", "")])


def _write_open_redirect_to_csv(writer: csv.writer, redirect_info: Dict[str, Any]):
    """
    Writes Open Redirect scan results to the provided CSV writer.
    """

    vulnerable_urls = redirect_info.get("vulnerable_urls", [])
    if not vulnerable_urls:
        writer.writerow(["No potential open redirects found."])
        return

    headers = ["vulnerable_url", "redirects_to"]
    writer.writerow(headers)

    for item in vulnerable_urls:
        writer.writerow([item.get("url", ""), item.get("redirects_to", "")])


# --- New Data-Driven Dispatch Table ---
CSV_DISPATCH_TABLE = {
    "records_info": {
        "title": "DNS Records",
        "writer_func": _write_dns_records_to_csv,
    },
    "whois_info": {"title": "WHOIS Information", "writer_func": _write_whois_to_csv},
    "mail_info": {
        "title": "Email Security Information",
        "writer_func": _write_mail_info_to_csv,
    },
    "headers_info": {
        "title": "HTTP Security Headers Analysis",
        "writer_func": _write_http_headers_to_csv,
    },
    "security_info": {
        "title": "Security Audit Findings",
        "writer_func": _write_security_audit_to_csv,
    },
    "ssl_info": {
        "title": "SSL/TLS Certificate Analysis",
        "writer_func": _write_ssl_info_to_csv,
    },
    "geo_info": {"title": "IP Geolocation", "writer_func": _write_geolocation_to_csv},
    "port_scan_info": {
        "title": "Open Port Scan",
        "writer_func": _write_port_scan_to_csv,
    },
    "takeover_info": {
        "title": "Subdomain Takeover",
        "writer_func": _write_subdomain_takeover_to_csv,
    },
    "dnsbl_info": {
        "title": "DNS Blocklist (DNSBL) Check",
        "writer_func": _write_dnsbl_to_csv,
    },
    "cloud_info": {
        "title": "Cloud Service Enumeration",
        "writer_func": _write_cloud_enum_to_csv,
    },
    "open_redirect_info": {
        "title": "Open Redirect Scan",
        "writer_func": _write_open_redirect_to_csv,
    },
}


def output(all_data: Dict[str, Any], output_path: Optional[str] = None):
    """
    Generates and prints a comprehensive CSV report to standard output,
    including sections for DNS records, WHOIS info, and more.

    Args:
        all_data: The dictionary containing all scan data.
        output_path: If provided, the output is written to this file path.
    """
    output_io = io.StringIO()
    writer = csv.writer(output_io)

    # Iterate through the main dispatch table to determine which modules were run
    for module_name, module_config in MODULE_DISPATCH_TABLE.items():
        data_key = module_config["data_key"]
        module_data = all_data.get(data_key)

        # Find the corresponding CSV writer configuration
        csv_config = CSV_DISPATCH_TABLE.get(data_key)
        if not csv_config:
            continue  # Skip if there's no CSV writer for this module

        writer.writerow([csv_config["title"]])

        # Check if data is missing or has an error
        if not module_data or (isinstance(module_data, dict) and module_data.get("error")):
            writer.writerow([f"No {csv_config['title'].lower()} found."])
        else:
            # Call the specific writer function
            # Special case for dns_records which needs domain and timestamp
            if data_key == "records_info":
                csv_config["writer_func"](
                    writer,
                    all_data.get("domain"),
                    all_data.get("scan_timestamp"),
                    module_data,
                )
            else:
                csv_config["writer_func"](writer, module_data)

        writer.writerow([])  # Add a blank line for separation

    csv_content = output_io.getvalue().strip()

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_content)
        except IOError as e:
            console.print(f"[bold red]Error writing CSV file to {output_path}: {e}[/bold red]")
    else:
        builtins.print(csv_content)
