#!/usr/bin/env python3
"""
Zone-Poker - Module Dispatch Table
This file acts as the central configuration for all available modules.
"""
import argparse

from modules.analysis.cloud_enum import enumerate_cloud_services
from modules.analysis.content_hash import get_content_hashes
from modules.analysis.critical_findings import aggregate_critical_findings
from modules.analysis.ct_logs import search_ct_logs
from modules.analysis.dane_analysis import analyze_dane_records
from modules.analysis.dns_ptr import reverse_ptr_lookups

# --- THIS IS THE FIX: Import analysis functions from their specific modules ---
from modules.analysis.dns_records import get_dns_records
from modules.analysis.dns_zone import attempt_axfr
from modules.analysis.dnsbl import check_dnsbl
from modules.analysis.email_sec import email_security_analysis
from modules.analysis.http_headers import analyze_http_headers
from modules.analysis.ip_geolocation import geolocate_ips
from modules.analysis.ns_info import nameserver_analysis
from modules.analysis.open_redirect import check_open_redirect
from modules.analysis.osint import osint_enrichment
from modules.analysis.port_scan import scan_ports
from modules.analysis.propagation import propagation_check
from modules.analysis.reputation import analyze_reputation
from modules.analysis.robots_txt import analyze_robots_txt
from modules.analysis.security_audit import security_audit
from modules.analysis.security_txt import check_security_txt
from modules.analysis.smtp_analysis import analyze_smtp_servers
from modules.analysis.ssl_analysis import analyze_ssl_certificate
from modules.analysis.subdomain_takeover import check_subdomain_takeover
from modules.analysis.tech import detect_technologies
from modules.analysis.waf_detection import detect_waf
from modules.analysis.whois import whois_lookup

# Import all display and export functions
from modules.display import (  # Only display functions remain here
    display_axfr_results,
    display_cloud_enum,
    display_content_hash_info,
    display_ct_logs,
    display_dane_analysis,
    display_dns_records_table,
    display_dnsbl_check,
    display_email_security,
    display_http_headers,
    display_ip_geolocation,
    display_nameserver_analysis,
    display_open_redirect,
    display_osint_results,
    display_port_scan,
    display_propagation,
    display_ptr_lookups,
    display_reputation_info,
    display_robots_txt,
    display_security_audit,
    display_security_txt,
    display_smtp_info,
    display_ssl_info,
    display_subdomain_takeover,
    display_technology_info,
    display_waf_detection,
    display_whois_info,
)
from modules.export_txt import (  # All txt export functions are imported
    export_txt_cloud_enum,
    export_txt_content_hash,
    export_txt_ct_logs,
    export_txt_dane,
    export_txt_dnsbl_check,
    export_txt_geolocation,
    export_txt_http_headers,
    export_txt_mail,
    export_txt_nsinfo,
    export_txt_open_redirect,
    export_txt_osint,
    export_txt_port_scan,
    export_txt_propagation,
    export_txt_ptr,
    export_txt_records,
    export_txt_reputation,
    export_txt_robots_txt,
    export_txt_security,
    export_txt_security_txt,
    export_txt_smtp,
    export_txt_ssl,
    export_txt_subdomain_takeover,
    export_txt_tech,
    export_txt_waf_detection,
    export_txt_whois,
    export_txt_zone,
)

# The MODULE_DISPATCH_TABLE is the central configuration for the orchestrator.
# It maps a module's command-line name (e.g., "records") to its corresponding
# analysis function, display function, and dependencies.
#
# - data_key: The key used to store the module's results in the `all_data` dictionary.
# - analysis_func: The function from the `analysis` module to call.
# - display_func: The function from the `display` module to call.
# - export_func: The function from `display` to format data for .txt reports.
# - arg_info: A dictionary defining the command-line argument for this module.
# - description: A user-friendly message shown when the module starts.
# - dependencies: A list of other modules that must run before this one.
MODULE_DISPATCH_TABLE = {
    "records": {
        "data_key": "records_info",
        "analysis_func": get_dns_records,
        "display_func": display_dns_records_table,
        "export_func": export_txt_records,
        "description": "Querying DNS records...",
        "arg_info": {
            "short": "-r",
            "long": "--records",
            "help": "Query all standard DNS record types.",
        },
    },
    "ptr": {
        "data_key": "ptr_info",
        "analysis_func": reverse_ptr_lookups,
        "display_func": display_ptr_lookups,
        "export_func": export_txt_ptr,
        "description": "Performing reverse DNS (PTR) lookups...",
        "dependencies": ["records"],
        "arg_info": {
            "short": None,
            "long": "--ptr",
            "help": "Perform reverse DNS (PTR) lookups for A/AAAA records.",
        },
    },
    "zone": {
        "data_key": "zone_info",
        "analysis_func": attempt_axfr,
        "display_func": display_axfr_results,
        "export_func": export_txt_zone,
        "description": "Attempting zone transfer (AXFR)...",
        "dependencies": ["records"],
        "arg_info": {
            "short": "-z",
            "long": "--zone",
            "help": "Attempt a zone transfer (AXFR) against nameservers.",
        },
    },
    "mail": {
        "data_key": "mail_info",
        "analysis_func": email_security_analysis,
        "display_func": display_email_security,
        "export_func": export_txt_mail,
        "description": "Analyzing email security (SPF, DMARC)...",
        "dependencies": ["records", "http_headers"],
        "arg_info": {
            "short": "-m",
            "long": "--mail",
            "help": "Analyze email security records (SPF, DMARC, DKIM).",
        },
    },
    "whois": {
        "data_key": "whois_info",
        "analysis_func": whois_lookup,
        "display_func": display_whois_info,
        "export_func": export_txt_whois,
        "description": "Performing WHOIS lookup...",
        "arg_info": {
            "short": "-w",
            "long": "--whois",
            "help": "Perform an extended WHOIS lookup on the domain.",
        },
    },
    "nsinfo": {
        "data_key": "nsinfo_info",
        "analysis_func": nameserver_analysis,
        "display_func": display_nameserver_analysis,
        "export_func": export_txt_nsinfo,
        "description": "Analyzing nameservers...",
        "dependencies": ["records"],
        "arg_info": {
            "short": "-n",
            "long": "--nsinfo",
            "help": "Analyze nameserver information and check for DNSSEC.",
        },
    },
    "propagation": {
        "data_key": "propagation_info",
        "analysis_func": propagation_check,
        "display_func": display_propagation,
        "export_func": export_txt_propagation,
        "description": "Checking DNS propagation...",
        "arg_info": {
            "short": "-p",
            "long": "--propagation",
            "help": "Check DNS propagation across public resolvers.",
        },
    },
    "security": {
        "data_key": "security_info",
        "analysis_func": security_audit,
        "display_func": display_security_audit,
        "export_func": export_txt_security,
        "description": "Auditing for security misconfigurations...",
        "dependencies": [
            "records",
            "mail",
            "nsinfo",
            "zone",
            "http_headers",
            "ssl",
            "takeover",
            "dnsbl",
            "port_scan",
            "security_txt",
            "reputation",
            "redirect",
            "robots",
        ],
        "arg_info": {
            "short": "-s",
            "long": "--security",
            "help": "Run a comprehensive audit for security misconfigurations.",
        },
    },
    "tech": {
        "data_key": "tech_info",
        "analysis_func": detect_technologies,
        "display_func": display_technology_info,
        "export_func": export_txt_tech,
        "dependencies": ["http_headers"],
        "description": "Detecting web technologies...",
        "arg_info": {
            "short": "-t",
            "long": "--tech",
            "help": "Detect web technologies, CMS, and security headers.",
        },
    },
    "osint": {
        "data_key": "osint_info",
        "analysis_func": osint_enrichment,
        "display_func": display_osint_results,
        "export_func": export_txt_osint,
        "description": "Gathering OSINT data...",
        "arg_info": {
            "short": "-o",
            "long": "--osint",
            "help": "Enrich data with passive DNS and other OSINT sources.",
        },
    },
    "ssl": {
        "data_key": "ssl_info",
        "analysis_func": analyze_ssl_certificate,
        "display_func": display_ssl_info,
        "export_func": export_txt_ssl,
        "dependencies": ["http_headers"],
        "description": "Analyzing SSL/TLS certificate...",
        "arg_info": {
            "short": None,
            "long": "--ssl",
            "help": "Analyze the SSL/TLS certificate.",
        },
    },
    "smtp": {
        "data_key": "smtp_info",
        "analysis_func": analyze_smtp_servers,
        "display_func": display_smtp_info,
        "export_func": export_txt_smtp,
        "description": "Analyzing mail server (SMTP) configuration...",
        "dependencies": ["records"],
        "arg_info": {
            "short": None,
            "long": "--smtp",
            "help": "Analyze mail servers (banner, STARTTLS).",
        },
    },
    "reputation": {
        "data_key": "reputation_info",  # This one already follows the convention
        "analysis_func": analyze_reputation,
        "display_func": display_reputation_info,
        "export_func": export_txt_reputation,
        "description": "Checking IP reputation (AbuseIPDB)...",
        "dependencies": ["records"],
        "arg_info": {
            "short": None,
            "long": "--reputation",
            "help": "Check IP reputation using AbuseIPDB.",
        },
    },
    "hashes": {
        "data_key": "hashes_info",
        "analysis_func": get_content_hashes,
        "display_func": display_content_hash_info,
        "export_func": export_txt_content_hash,
        "description": "Fetching content and favicon hashes...",
        "arg_info": {
            "short": None,
            "long": "--hashes",
            "help": "Get Murmur32 favicon and SHA256 page content hashes.",
        },
    },
    "ct": {
        "data_key": "ct_info",
        "analysis_func": search_ct_logs,
        "display_func": display_ct_logs,
        "export_func": export_txt_ct_logs,
        "description": "Searching Certificate Transparency logs...",
        "arg_info": {
            "short": None,
            "long": "--ct",
            "help": "Find subdomains from Certificate Transparency logs.",
        },
    },
    "waf": {
        "data_key": "waf_info",
        "analysis_func": detect_waf,
        "display_func": display_waf_detection,
        "export_func": export_txt_waf_detection,
        "description": "Detecting Web Application Firewall...",
        "arg_info": {
            "short": None,
            "long": "--waf",
            "help": "Attempt to identify a Web Application Firewall.",
        },
    },
    "dane": {
        "data_key": "dane_info",
        "analysis_func": analyze_dane_records,
        "display_func": display_dane_analysis,
        "export_func": export_txt_dane,
        "dependencies": ["http_headers"],
        "description": "Checking for DANE (TLSA) records...",
        "arg_info": {
            "short": None,
            "long": "--dane",
            "help": "Check for DANE (TLSA) records for HTTPS.",
        },
    },
    "geolocation": {
        "data_key": "geo_info",
        "analysis_func": geolocate_ips,
        "display_func": display_ip_geolocation,
        "export_func": export_txt_geolocation,
        "description": "Geolocating IP addresses...",
        "dependencies": ["records", "http_headers"],
        "arg_info": {
            "short": None,
            "long": "--geo",
            "help": "Geolocate IP addresses from A/AAAA records.",
        },
    },
    "http_headers": {
        "data_key": "headers_info",
        "analysis_func": analyze_http_headers,
        "display_func": display_http_headers,
        "export_func": export_txt_http_headers,
        "description": "Analyzing HTTP security headers...",
        "arg_info": {
            "short": None,
            "long": "--headers",
            "help": "Perform an in-depth analysis of HTTP security headers.",
        },
    },
    "port_scan": {
        "data_key": "port_scan_info",
        "analysis_func": scan_ports,
        "display_func": display_port_scan,
        "export_func": export_txt_port_scan,
        "description": "Scanning for open ports...",
        "dependencies": ["records", "http_headers"],
        "arg_info": {
            "short": None,
            "long": "--ports",
            "help": "Scan for common open TCP ports on discovered IPs.",
        },
    },
    "takeover": {
        "data_key": "takeover_info",
        "analysis_func": check_subdomain_takeover,
        "display_func": display_subdomain_takeover,
        "export_func": export_txt_subdomain_takeover,
        "description": "Checking for subdomain takeovers...",
        "dependencies": ["records"],
        "arg_info": {
            "short": None,
            "long": "--takeover",
            "help": "Check for potential subdomain takeovers.",
        },
    },
    "cloud": {
        "data_key": "cloud_info",
        "analysis_func": enumerate_cloud_services,
        "display_func": display_cloud_enum,
        "export_func": export_txt_cloud_enum,
        "description": "Enumerating cloud services...",
        "arg_info": {
            "short": None,
            "long": "--cloud",
            "help": "Enumerate common cloud services (e.g., S3 buckets).",
        },
    },
    "dnsbl": {
        "data_key": "dnsbl_info",
        "analysis_func": check_dnsbl,
        "display_func": display_dnsbl_check,
        "export_func": export_txt_dnsbl_check,
        "description": "Checking IPs against DNS blocklists...",
        "dependencies": ["records"],
        "arg_info": {
            "short": None,
            "long": "--dnsbl",
            "help": "Check discovered IPs against common DNS blocklists.",
        },
    },
    "redirect": {
        "data_key": "redirect_info",
        "analysis_func": check_open_redirect,
        "display_func": display_open_redirect,
        "export_func": export_txt_open_redirect,
        "description": "Checking for open redirect vulnerabilities...",
        "dependencies": [],
        "arg_info": {
            "short": None,
            "long": "--redirect",
            "help": "Check for common open redirect vulnerabilities.",
        },
    },
    "security_txt": {
        "data_key": "security_txt_info",
        "analysis_func": check_security_txt,
        "display_func": display_security_txt,
        "export_func": export_txt_security_txt,
        "description": "Checking for security.txt file...",
        "arg_info": {
            "short": None,
            "long": "--security-txt",
            "help": "Check for a security.txt file and parse its contents.",
        },
    },
    # This is a meta-module that doesn't have its own display/export functions
    "robots": {
        "data_key": "robots_info",
        "analysis_func": analyze_robots_txt,
        "display_func": display_robots_txt,
        "export_func": export_txt_robots_txt,
        "description": "Checking for robots.txt file...",
        "arg_info": {
            "short": None,
            "long": "--robots",
            "help": "Check for a robots.txt file and analyze its contents.",
        },
    },
    # in the traditional sense. It's used to aggregate data for summary views.
    "critical_findings": {
        "data_key": "critical_findings_info",
        "analysis_func": aggregate_critical_findings,
        "display_func": None,  # Handled by the main summary display
        "export_func": None,  # Handled by the main summary export
        "description": "Aggregating critical findings...",
        "dependencies": [
            "zone",
            "takeover",
            "ssl",
            "reputation",
            "mail",
        ],
        "arg_info": None,  # Not a user-callable module
    },
}


def register_module_args(parser: argparse.ArgumentParser):
    """
    Adds command-line arguments for each module to the argument parser.
    """
    for name, details in MODULE_DISPATCH_TABLE.items():
        arg_info = details.get("arg_info")
        if arg_info:
            # Simplify argument creation by convention.
            # The long argument is assumed to be '--<module_name>'
            # unless specified otherwise.
            long_arg = arg_info.get("long", f"--{name}")

            args = [arg for arg in [arg_info.get("short"), long_arg] if arg]
            if args:
                parser.add_argument(
                    *args,
                    dest=name,
                    action="store_true",
                    help=arg_info.get("help", ""),
                )
