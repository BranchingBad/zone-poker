#!/usr/bin/env python3
from typing import Dict, List, Any

def security_audit(
    records: Dict[str, List[Dict[str, Any]]],
    email_security: Dict[str, Any],
    nameserver_info: Dict[str, Any],
    zone_info: Dict[str, Any],
    **kwargs
) -> Dict[str, Dict[str, str]]:
    """Runs a comprehensive audit for DNS and web security misconfigurations."""
    audit: Dict[str, Dict[str, str]] = {}
    
    # SPF Policy
    spf_data = email_security.get("spf", {})
    if "warning" in spf_data:
        audit["SPF Record"] = {"status": "Weak", "details": spf_data["warning"]}
    elif spf_data.get("all_policy") == "?all":
        audit["SPF Policy"] = {"status": "Weak", "details": "Policy is '?all' (Neutral), which does not prevent spoofing."}
    elif spf_data.get("all_policy") == "~all":
        audit["SPF Policy"] = {"status": "Moderate", "details": "Policy is '~all' (SoftFail), which is not fully secure."}
    elif spf_data.get("all_policy") == "-all":
        audit["SPF Policy"] = {"status": "Secure", "details": "Policy is '-all' (HardFail), which is the recommended setting."}
    else:
        audit["SPF Policy"] = {"status": "Weak", "details": "No SPF record or 'all' mechanism found."}

    # DMARC Policy
    dmarc_data = email_security.get("dmarc", {})
    if dmarc_data.get("p") == "none":
        details = "Policy 'p=none' is in monitoring mode and does not prevent spoofing."
        if not dmarc_data.get("rua"):
            details += " Additionally, no 'rua' reporting address is configured."
        audit["DMARC Policy"] = {"status": "Weak", "details": details}
    elif dmarc_data.get("p") in ("quarantine", "reject"):
        audit["DMARC Policy"] = {"status": "Secure", "details": f"Policy is '{dmarc_data['p']}', which protects against spoofing."}
    else:
        audit["DMARC Policy"] = {"status": "Weak", "details": "No DMARC record found or policy is misconfigured."}

    # CAA Record
    if records.get("CAA"):
        audit["CAA Record"] = {"status": "Secure", "details": "Present, restricting which CAs can issue certificates."}
    else:
        audit["CAA Record"] = {"status": "Weak", "details": "Not found, allowing any Certificate Authority to issue certificates."}

    # DNSSEC
    dnssec_status = nameserver_info.get("dnssec", "Not Enabled")
    if dnssec_status.startswith("Enabled"):
        dnssec_final_status = "Secure"
    elif dnssec_status.startswith("Partial"):
        dnssec_final_status = "Moderate"
    else: # "Not Enabled" or other cases
        dnssec_final_status = "Weak"
    audit["DNSSEC"] = {"status": dnssec_final_status, "details": dnssec_status}

    # Zone Transfer
    axfr_summary = zone_info.get("summary", "Not Checked")
    audit["Zone Transfer"] = {"status": "Vulnerable" if "Vulnerable" in axfr_summary else "Secure", "details": axfr_summary}

    return audit