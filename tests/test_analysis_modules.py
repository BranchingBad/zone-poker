#!/usr/bin/env python3
"""
Unit tests for the analysis modules in Zone-Poker.
"""
import pytest
import respx
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import RequestError
from datetime import datetime, timedelta

from modules.analysis.http_headers import HEADER_CHECKS
from modules.analysis.security_audit import security_audit, AUDIT_CHECKS
from modules.analysis.tech import detect_technologies
from modules.analysis.whois import whois_lookup

# --- Test Data Fixtures ---
from modules.analysis.critical_findings import aggregate_critical_findings

from modules.analysis.ct_logs import search_ct_logs
from modules.analysis.open_redirect import check_open_redirect


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
        },  # No error key
        "takeover_info": {"vulnerable": []},
        "dnsbl_info": {"listed_ips": []},
        "port_scan_info": {},
        "reputation_info": {"1.2.3.4": {"abuseConfidenceScore": 10}},
        "redirect_info": {"vulnerable_urls": []},
    }


@pytest.fixture
def mock_weak_data():
    """Provides mock data representing a weak or misconfigured setup."""
    past_timestamp = (datetime.now() - timedelta(days=1)).timestamp()
    return {
        "records_info": {},  # No CAA, NSEC, or NSEC3 records
        "mail_info": {
            "spf": {"all_policy": "?all"},
            "dmarc": {"p": "none"},  # No rua address
        },
        "nsinfo_info": {"dnssec": "Not Enabled (No DNSKEY or DS records)"},
        "zone_info": {"summary": "Vulnerable (Zone Transfer Successful)"},
        "headers_info": {
            "analysis": {
                "Content-Security-Policy": {
                    "status": "Missing",
                    "recommendation": "Implement CSP.",
                }
            }
        },
        "ssl_info": {"valid_until": past_timestamp},  # Expired cert
        "takeover_info": {"vulnerable": [{"subdomain": "test.example.com"}]},
        "dnsbl_info": {"listed_ips": [{"ip": "1.2.3.4"}]},
        "port_scan_info": {"1.2.3.4": [80, 443]},
        "reputation_info": {"1.2.3.4": {"abuseConfidenceScore": 95}},
        "redirect_info": {"vulnerable_urls": [{"url": "http://a.com"}]},
    }


@pytest.fixture
def mock_moderate_data(mock_secure_data):
    """Provides mock data for 'Moderate' checks, based on the secure data."""
    mock_secure_data["headers_info"]["analysis"]["Strict-Transport-Security"] = {  # type: ignore
        "status": "Weak",
        "recommendation": "HSTS 'max-age' is less than one year.",
    }
    return mock_secure_data


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
                "X-Frame-Options": {"status": "Missing", "recommendation": "..."}
            }
        },
    }


@pytest.fixture
def mock_weak_cipher_data():
    """Provides mock data for a weak SSL/TLS cipher suite."""
    return {
        "ssl_info": {
            "cipher": ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1.2", 112),
        },
        "headers_info": {"analysis": {}},
        "mail_info": {},
        # Add other keys to prevent KeyErrors if the audit function expects them
    }


@pytest.fixture
def mock_critical_data():
    """Provides mock data for a critical SPF misconfiguration."""
    return {
        "mail_info": {"spf": {"all_policy": "+all"}},
        "headers_info": {"analysis": {}},
    }


def test_security_audit_secure(mock_secure_data):
    """
    Tests the security_audit function with data that should result in all 'Secure' statuses.
    """
    # The `security_audit` function now expects a single `all_data` dictionary.
    result = security_audit(all_data=mock_secure_data)
    assert not result["findings"]


def test_security_audit_weak(mock_weak_data):
    """
    Tests the security_audit function with data that should result in 'Weak' or
    'Vulnerable' statuses.
    """
    result = security_audit(all_data=mock_weak_data)

    # Convert list of findings to a dict for easier assertions
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


def test_security_audit_moderate(mock_moderate_data):
    """
    Tests a specific case that should result in a 'Moderate' status.
    """
    result = security_audit(all_data=mock_moderate_data)
    hsts_finding = next(
        f
        for f in result["findings"]
        if f["finding"] == "Insecure Header: Strict-Transport-Security"
    )
    assert hsts_finding["severity"] == "High"
    assert "HSTS 'max-age' is less than one year" in hsts_finding["recommendation"]


def test_security_audit_weak_cipher(mock_weak_cipher_data):
    """
    Tests that a weak cipher suite is correctly flagged.
    """
    result = security_audit(all_data=mock_weak_cipher_data)
    weak_cipher_finding = next(
        f for f in result["findings"] if f["finding"] == "Weak SSL/TLS Cipher Suite"
    )
    assert weak_cipher_finding["severity"] == "High"


def test_all_security_checks_are_covered(
    mock_weak_data,
    mock_moderate_data,
    mock_missing_data,
    mock_weak_cipher_data,
    mock_critical_data,
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
    all_defined_checks = all_check_names.union(all_header_check_names)

    # 2. Run all mock data through the security audit to see what findings they produce
    all_mock_data = [
        mock_weak_data,
        mock_moderate_data,
        mock_missing_data,
        mock_weak_cipher_data,
        mock_critical_data,
    ]
    all_triggered_findings = set()

    for data in all_mock_data:
        result = security_audit(all_data=data)
        for finding in result["findings"]:
            all_triggered_findings.add(finding["finding"])

    # 3. Find the difference
    uncovered_checks = all_defined_checks - all_triggered_findings

    assert not uncovered_checks, (
        f"The following security checks are not covered by any tests: "
        f"{sorted(list(uncovered_checks))}"
    )


@pytest.mark.asyncio
@respx.mock
async def test_detect_technologies_found():
    """
    Tests that detect_technologies correctly identifies technologies.
    It checks headers, HTML content, and script tags.
    """
    domain = "tech-example.com"
    # Mock a response that contains multiple fingerprints
    mock_html = """
    <html>
        <head>
            <meta name="generator" content="Joomla! 1.5 - Open Source Content Management" />
        </head>
        <body>
            <div class="wp-content">Some WordPress content</div>
            <script src="/assets/react.js"></script>
        </body>
    </html>
    """
    mock_headers = {"X-Powered-By": "PHP/8.1"}
    respx.get(f"https://{domain}").respond(200, headers=mock_headers, html=mock_html)

    result = await detect_technologies(domain=domain, timeout=5, verbose=False)

    assert "WordPress" in result["technologies"]
    assert "Joomla" in result["technologies"]
    assert "React" in result["technologies"]
    assert any(tech.startswith("PHP") for tech in result["technologies"])


@pytest.mark.asyncio
async def test_whois_lookup_success():
    """
    Tests a successful whois_lookup, including data normalization of lists and
    datetimes.
    """
    mock_whois_data = MagicMock()
    mock_whois_data.text = "raw whois text"
    # Simulate the data structure returned by the python-whois library
    mock_whois_data.items.return_value = [
        ("domain_name", ["EXAMPLE.COM"]),  # whois can return a list
        ("creation_date", [datetime(2020, 1, 1)]),
        ("registrar", "Test Registrar"),
        ("emails", ["abuse@example.com", "admin@example.com"]),
    ]

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.return_value = mock_whois_data
        result = await whois_lookup(domain="example.com", verbose=False)

    # Check that the first item in the list is taken
    assert result["domain_name"] == "EXAMPLE.COM"
    # Check that datetime is formatted to string
    assert result["creation_date"] == "2020-01-01T00:00:00"
    assert result["registrar"] == "Test Registrar"  # type: ignore
    # Check that emails are joined  # type: ignore
    assert result["emails"] == "abuse@example.com"  # type: ignore
    assert "error" not in result  # type: ignore


@pytest.mark.asyncio
async def test_whois_lookup_no_data_returned():
    """
    Tests the case where the whois query runs but returns an empty result.
    """
    mock_whois_data = MagicMock()
    mock_whois_data.text = ""  # The check for success is based on the .text attribute
    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.return_value = mock_whois_data
        result = await whois_lookup(domain="example.com", verbose=False)

    assert result["error"] == "No WHOIS data returned from server."


@pytest.mark.asyncio
async def test_whois_lookup_pywhois_error():
    """Tests the handling of a generic Exception during WHOIS lookup."""
    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = Exception("Domain not found.")
        result = await whois_lookup(domain="nonexistent.com", verbose=False)

    assert "An unexpected error occurred: Domain not found." in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_check_open_redirect_vulnerable_found():
    """
    Tests that check_open_redirect correctly identifies a vulnerable URL.
    """
    domain = "vulnerable-site.com"
    vulnerable_payload = "/?next=https://example.com"
    vulnerable_url = f"https://{domain}{vulnerable_payload}"

    # Mock the request to the vulnerable URL to return a 302 redirect
    respx.get(vulnerable_url).respond(
        302, headers={"Location": "https://example.com/malicious"}
    )

    # Mock other payloads to return non-redirect responses
    respx.get(f"https://{domain}//example.com").respond(200)
    respx.get(f"https://{domain}//www.google.com").respond(200)
    respx.get(f"https://{domain}/login?redirect=https://example.com").respond(404)

    result = await check_open_redirect(domain=domain, timeout=5)

    assert len(result["vulnerable_urls"]) == 1
    finding = result["vulnerable_urls"][0]
    assert finding["url"] == vulnerable_url
    assert finding["redirects_to"] == "https://example.com/malicious"


@pytest.mark.asyncio
@respx.mock
async def test_check_open_redirect_not_vulnerable():
    """
    Tests that check_open_redirect handles non-vulnerable cases correctly,
    including safe redirects and network errors.
    """
    domain = "safe-site.com"

    # Mock a redirect to a safe, internal path
    respx.get(f"https://{domain}/?next=https://example.com").respond(
        302, headers={"Location": "/dashboard"}
    )
    # Mock a normal 200 OK response
    respx.get(f"https://{domain}//example.com").respond(200)
    respx.get(f"https://{domain}//www.google.com").respond(200)
    # Mock a request that results in a network error
    respx.get(f"https://{domain}/login?redirect=https://example.com").mock(
        side_effect=RequestError("Connection failed")
    )

    result = await check_open_redirect(domain=domain, timeout=5)

    assert len(result["vulnerable_urls"]) == 0


def test_aggregate_critical_findings_found():
    """
    Tests that aggregate_critical_findings correctly identifies multiple critical issues.
    """
    # This test now relies on the output of security_audit
    mock_data = {
        "security_info": {
            "findings": [
                {
                    "finding": "Subdomain Takeover",
                    "severity": "Critical",
                    "recommendation": "Remove dangling DNS records.",
                },
                {
                    "finding": "Zone Transfer (AXFR) Enabled",
                    "severity": "High",
                    "recommendation": "Disable zone transfers.",
                },
                {
                    "finding": "Expired SSL/TLS Certificate",
                    "severity": "High",
                    "recommendation": "Renew the certificate.",
                },
                {
                    "finding": "Weak DMARC Policy (p=none)",
                    "severity": "Medium",
                    "recommendation": "Transition to p=reject.",
                },
            ]
        }
    }

    result = aggregate_critical_findings(mock_data)
    findings = result.get("critical_findings", [])

    assert len(findings) == 3  # Should only include Critical and High
    assert "Subdomain Takeover: Remove dangling DNS records." in findings
    assert "Zone Transfer (AXFR) Enabled: Disable zone transfers." in findings
    assert "Expired SSL/TLS Certificate: Renew the certificate." in findings
    # Ensure the Medium severity finding is NOT included
    assert not any("DMARC" in f for f in findings)


def test_aggregate_critical_findings_none_found():
    """
    Tests that aggregate_critical_findings returns an empty list when no
    critical issues are present. It also tests handling of missing data.
    """
    mock_data = {
        "security_info": {
            "findings": [
                {
                    "finding": "Missing CAA Record",
                    "severity": "Low",
                    "recommendation": "Implement CAA.",
                },
                {
                    "finding": "Weak DMARC Policy (p=none)",
                    "severity": "Medium",
                    "recommendation": "Transition to p=reject.",
                },
            ]
        }
    }

    result = aggregate_critical_findings(mock_data)
    findings = result.get("critical_findings", [])

    assert len(findings) == 0

    # Test with completely empty data
    result_empty = aggregate_critical_findings({})
    assert len(result_empty.get("critical_findings", [])) == 0


@pytest.mark.asyncio
@respx.mock
async def test_search_ct_logs_dual_query():
    """
    Tests that search_ct_logs correctly performs two queries (wildcard and base domain),
    combines the results, and removes duplicates.
    """
    domain = "example.com"
    wildcard_url = f"https://crt.sh/?q=%.{domain}&output=json"
    base_url = f"https://crt.sh/?q={domain}&output=json"

    # Mock response for the wildcard query
    wildcard_response_data = [
        {"name_value": "one.example.com"},
        {"name_value": "two.example.com"},
        {"name_value": "*.example.com"},  # Should be filtered out
    ]
    respx.get(wildcard_url).respond(200, json=wildcard_response_data)

    # Mock response for the base domain query (with an overlapping entry)
    base_response_data = [
        {"name_value": "two.example.com"},  # Duplicate
        {"name_value": "three.example.com"},
        {"name_value": "example.com"},  # Should be filtered out
    ]
    respx.get(base_url).respond(200, json=base_response_data)

    result = await search_ct_logs(domain=domain, timeout=5)

    assert "error" not in result or result["error"] is None
    assert result["subdomains"] == [
        "one.example.com",
        "three.example.com",
        "two.example.com",
    ]


@pytest.mark.asyncio
@respx.mock
async def test_search_ct_logs_one_query_fails():
    """
    Tests that search_ct_logs continues gracefully if one of the two queries fails.
    """
    domain = "example.com"
    wildcard_url = f"https://crt.sh/?q=%.{domain}&output=json"
    base_url = f"https://crt.sh/?q={domain}&output=json"

    # Mock a successful response for the wildcard query
    wildcard_response_data = [{"name_value": "one.example.com"}]
    respx.get(wildcard_url).respond(200, json=wildcard_response_data)

    # Mock a server error for the base domain query
    respx.get(base_url).respond(500)

    result = await search_ct_logs(domain=domain, timeout=5)

    # The function should not report an error and should return the valid results.
    assert "error" not in result or result["error"] is None
    assert result["subdomains"] == ["one.example.com"]
