#!/usr/bin/env python3
from typing import Dict, List, Any

def security_audit(records: Dict[str, List[Dict[str, Any]]], email_security: Dict[str, Any]) -> Dict[str, str]:
    """Runs a basic audit for DNS security misconfigurations."""
    audit = {}
    
    # SPF Policy
    if email_security.get("spf", {}).get("all_policy") == "?all":
        audit["SPF Policy"] = "Weak (Using '?all' Neutral policy)"
    elif email_security.get("spf", {}).get("all_policy") == "~all":
        audit["SPF Policy"] = "Moderate (Using '~all' SoftFail policy)"
    elif email_security.get("spf", {}).get("all_policy") == "-all":
        audit["SPF Policy"] = "Secure (Using '-all' HardFail policy)"
    else:
        audit["SPF Policy"] = "Weak (No 'all' policy or record not found)"

    # DMARC Policy
    if email_security.get("dmarc", {}).get("p") == "none":
        audit["DMARC Policy"] = "Weak (Policy 'p=none' is in monitoring mode)"
    elif email_security.get("dmarc", {}).get("p") in ("quarantine", "reject"):
        audit["DMARC Policy"] = f"Secure (Policy 'p={email_security['dmarc']['p']}')"
    else:
        audit["DMARC Policy"] = "Not Found or Misconfigured"

    # CAA Record
    if records.get("CAA"):
        audit["CAA Record"] = "Present (Restricts certificate issuance)"
    else:
        audit["CAA Record"] = "Not Found (Any CA can issue certificates)"

    return audit