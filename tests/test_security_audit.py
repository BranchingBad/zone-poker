#!/usr/bin/env python3
"""
Unit tests for the security_audit analysis module in Zone-Poker.
"""
import copy
from datetime import datetime, timedelta

import pytest

from modules.analysis.http_headers import HEADER_CHECKS
from modules.analysis.security_audit import AUDIT_CHECKS, security_audit

# --- Test Data Fixtures ---

# Note: All fixtures are correct as-of the previous version,
# including the deepcopy fix in mock_moderate_data.
# (Fixtures omitted for brevity, no changes needed)


@pytest.fixture
def mock_secure_data():
    """Provides mock data representing a secure configuration."""
    future_timestamp = (datetime.now() + timedelta(days=30)).timestamp()
    return {
        "records_info": {
            "CAA": [{"value": "0 issue 'letsencrypt.org'"}],
            "NSEC3": [{"value": "..."}],  # For secure zone walking check
        },
        "mail_info": {
            "spf": {"all_policy": "-all"},
            "dmarc": {"p": "reject", "rua": "mailto:dmarc@example.com"},
        },
        "nsinfo_info": {"dnssec": "Enabled (DNSKEY and DS records found)"},
        "zone_info": {"summary": "Secure (No successful transfers)"},
        "headers_info": {
            "analysis": {
                "Strict-Transport-Security": {"status": "Strong"},
                "Content-Security-Policy": {"status": "Present"},
            }
        },
        "ssl_info": {
            "valid_until": future_timestamp,
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        },
        "takeover_info": {"vulnerable": []},
        "reputation_info": {"1.2.3.4": {"abuseConfidenceScore": 10}},
        "redirect_info": {"vulnerable_urls": []},
        "robots_info": {"disallowed_sensitive": []},
    }


@pytest.fixture
def mock_weak_data():
    """Provides mock data representing a weak or misconfigured setup."""
    past_timestamp = (datetime.now() - timedelta(days=1)).timestamp()
    return {
        "records_info": {},  # No CAA, NSEC, or NSEC3 records
        "mail_info": {
            "spf": {"all_policy": "?all"},
            "dmarc": {"p": "none"},
        },
        "nsinfo_info": {"dnssec": "Not Enabled (No DNSKEY or DS records)"},
        "zone_info": {"summary": "Vulnerable (Zone Transfer Successful)"},
        "headers_info": {
            "analysis": {
                "Content-Security-Policy": {
                    "status": "Missing",
                    "recommendation": "Implement CSP.",
                },
                # Add missing headers to satisfy the coverage test
                "X-Content-Type-Options": {"status": "Missing"},
                "X-XSS-Protection": {"status": "Missing"},
                "Referrer-Policy": {"status": "Missing"},
                "Permissions-Policy": {"status": "Missing"},
            }
        },
        "ssl_info": {"valid_until": past_timestamp},  # Expired cert
        "takeover_info": {"vulnerable": [{"subdomain": "test.example.com"}]},
        "reputation_info": {"1.2.3.4": {"abuseConfidenceScore": 95}},
        "redirect_info": {"vulnerable_urls": [{"url": "http://a.com"}]},
        "robots_info": {},
    }


@pytest.fixture
def mock_moderate_data(mock_secure_data):
    """Provides mock data for 'Moderate' checks, based on the secure data."""
    # Use deepcopy to avoid modifying the cached 'mock_secure_data' fixture
    data = copy.deepcopy(mock_secure_data)
    data["headers_info"]["analysis"]["Strict-Transport-Security"] = {
        "status": "Weak",
        "recommendation": "HSTS 'max-age' is less than one year.",
    }
    return data


@pytest.fixture
def mock_missing_data():
    """Provides mock data for checks that look for completely missing data."""
    return {
        "mail_info": {
            "spf": {"status": "Not Found"},
            "dmarc": {"status": "Not Found"},
        },
        "headers_info": {
            "analysis": {
                "X-Frame-Options": {"status": "Missing", "recommendation": "..."},
            },
        },
    }


@pytest.fixture
def mock_weak_cipher_data():
    """Provides mock data for a weak SSL/TLS cipher suite."""
    return {
        "ssl_info": {
            "cipher": ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1.2", 112),
        },
    }


@pytest.fixture
def mock_critical_data():
    """Provides mock data for a critical SPF misconfiguration."""
    return {
        "mail_info": {"spf": {"all_policy": "+all"}},
    }


@pytest.fixture
def mock_robots_txt_data():
    """Provides mock data for sensitive paths found in robots.txt."""
    return {
        "robots_info": {
            "disallowed_sensitive": ["/admin", "/backup.zip"],
        },
    }


# --- Tests ---


def test_security_audit_secure(mock_secure_data):
    """
    Tests the security_audit function with data that should result in no findings.
    """
    result = security_audit(all_data=mock_secure_data)
    assert not result["findings"]


def test_security_audit_weak(mock_weak_data):
    """
    Tests the security_audit function with data that should result in multiple findings.
    """
    result = security_audit(all_data=mock_weak_data)
    findings = {f["finding"]: f for f in result["findings"]}

    assert findings["Subdomain Takeover"]["severity"] == "Critical"
    assert findings["Permissive SPF Policy (?all)"]["severity"] == "Medium"
    assert findings["Weak DMARC Policy (p=none)"]["severity"] == "Medium"
    assert findings["DNSSEC Not Enabled"]["severity"] == "Medium"
    assert findings["Zone Transfer (AXFR) Enabled"]["severity"] == "High"
    assert findings["Open Redirect"]["severity"] == "Medium"
    assert findings["Expired SSL/TLS Certificate"]["severity"] == "High"
    assert findings["High-Risk IP Reputation"]["severity"] == "High"
    assert (
        findings.get("Insecure Header: Content-Security-Policy")["severity"] == "High"
    )


def test_security_audit_robots_txt(mock_secure_data, mock_robots_txt_data):
    """
    Tests that sensitive paths in robots.txt are correctly flagged.
    """
    # Start with a secure baseline and add the specific vulnerability
    test_data = copy.deepcopy(mock_secure_data)
    # Use .update() which is correct for replacing this top-level key
    test_data.update(mock_robots_txt_data)

    result = security_audit(all_data=test_data)

    # This test will LIKELY STILL FAIL.
    # The failure (0 == 1) implies a bug in the security_audit()
    # function's logic for robots.txt.

    assert len(result["findings"]) == 1, "Should only find the robots.txt issue"
    finding = result["findings"][0]
    assert finding["finding"] == "Sensitive Paths in robots.txt"
    assert finding["severity"] == "Low"
    assert (
        "disallows crawling of 2 potentially sensitive path(s)"
        in finding["recommendation"]
    )


def test_all_security_checks_are_covered(
    mock_secure_data,
    mock_weak_data,
    mock_moderate_data,
    mock_missing_data,
    mock_weak_cipher_data,
    mock_critical_data,
    mock_robots_txt_data,
):
    """
    Meta-test to ensure that every check in AUDIT_CHECKS and HEADER_CHECKS
    is triggered by at least one of the mock data fixtures.
    """
    # 1. Get all defined finding names
    all_check_names = {check["finding"] for check in AUDIT_CHECKS}
    all_header_check_names = {
        f"Insecure Header: {name}" for name in HEADER_CHECKS.keys()
    }
    # Manually add the check that is not in the main lists
    all_check_names.add("Sensitive Paths in robots.txt")
    all_defined_checks = all_check_names.union(all_header_check_names)

    # 2. Run all mock data through the security audit to see what findings they produce
    all_mock_data = [
        mock_weak_data,
        mock_moderate_data,
        mock_missing_data,
        mock_weak_cipher_data,
        mock_critical_data,
        mock_robots_txt_data,
    ]
    all_triggered_findings = set()

    for data in all_mock_data:
        # Start with a deepcopy of the baseline to ensure isolation
        full_data = copy.deepcopy(mock_secure_data)

        # FIX: Use a custom merge strategy instead of deep_merge or .update()
        for key, value in data.items():
            if (
                key == "headers_info"
                and "analysis" in value
                and isinstance(full_data.get(key), dict)
            ):
                # Special case: merge the 'analysis' dict
                full_data[key]["analysis"].update(value["analysis"])
            else:
                # Default behavior: replace the top-level key
                full_data[key] = value

        result = security_audit(all_data=full_data)
        for finding in result["findings"]:
            all_triggered_findings.add(finding["finding"])

    # 3. Find the difference
    uncovered_checks = all_defined_checks - all_triggered_findings

    # This test will LIKELY STILL FAIL, but only for 'Sensitive Paths in robots.txt'
    assert not uncovered_checks, (
        f"The following security checks are not covered by any tests: "
        f"{sorted(list(uncovered_checks))}"
    )
