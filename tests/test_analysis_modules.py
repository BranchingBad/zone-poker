#!/usr/bin/env python3
"""
Unit tests for the analysis modules in Zone-Poker.
"""
import pytest
import respx
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import RequestError
from datetime import datetime, timedelta
from modules.analysis.security_audit import security_audit
from modules.analysis.tech import detect_technologies
from modules.analysis.whois import whois_lookup

# --- Test Data Fixtures ---
from modules.analysis.critical_findings import aggregate_critical_findings

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
    assert findings["Insecure Header: Content-Security-Policy"]["severity"] == "High"


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

    assert "WordPress" in result["technologies"]  # type: ignore
    assert "Joomla" in result["technologies"]  # From meta tag
    assert "React" in result["technologies"]  # type: ignore
    assert "PHP" in result["technologies"]  # From fingerprint on X-Powered-By header


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
