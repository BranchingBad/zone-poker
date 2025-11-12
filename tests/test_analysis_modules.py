#!/usr/bin/env python3
"""
Unit tests for the analysis modules in Zone-Poker.
"""
import pytest
import respx
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
from modules.analysis.security_audit import security_audit
from modules.analysis.tech import detect_technologies
from modules.analysis.whois import whois_lookup

# --- Test Data Fixtures ---


@pytest.fixture
def mock_secure_data():
    """Provides mock data representing a secure configuration."""
    future_timestamp = (datetime.now() + datetime.timedelta(days=30)).timestamp()
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
        "dnsbl_info": {"listed_ips": []},
        "port_scan_info": {},
        "reputation_info": {"1.2.3.4": {"abuseConfidenceScore": 10}},
    }


@pytest.fixture
def mock_weak_data():
    """Provides mock data representing a weak or misconfigured setup."""
    return {
        "records_info": {},  # No CAA record
        "NSEC": [{"value": "..."}],  # For weak zone walking check
        "mail_info": {
            "spf": {"all_policy": "?all"},
            "dmarc": {"p": "none"},  # No rua address
        },
        "nsinfo_info": {"dnssec": "Not Enabled (No DNSKEY or DS records)"},
        "zone_info": {"summary": "Vulnerable (Zone Transfer Successful)"},
        "headers_info": {
            "analysis": {"Content-Security-Policy": {"status": "Missing"}}
        },
        "ssl_info": {"error": "Certificate expired"},
        "takeover_info": {"vulnerable": [{"subdomain": "test.example.com"}]},
        "dnsbl_info": {"listed_ips": [{"ip": "1.2.3.4"}]},
        "port_scan_info": {"1.2.3.4": [80, 443]},
        "reputation_info": {"1.2.3.4": {"abuseConfidenceScore": 95}},
    }


@pytest.fixture
def mock_moderate_data(mock_secure_data):
    """Provides mock data for 'Moderate' checks, based on the secure data."""
    mock_secure_data["headers_info"]["analysis"]["Strict-Transport-Security"] = {
        "status": "Weak"
    }
    return mock_secure_data


def test_security_audit_secure(mock_secure_data):
    """
    Tests the security_audit function with data that should result in all 'Secure' statuses.
    """
    # The `security_audit` function now expects all dependency data.
    result = security_audit(**mock_secure_data)

    assert result["SPF Policy"]["status"] == "Secure"
    assert result["DMARC Policy"]["status"] == "Secure"
    assert result["CAA Record"]["status"] == "Secure"
    assert result["DNSSEC"]["status"] == "Secure"
    assert result["Zone Transfer"]["status"] == "Secure"
    assert result["HSTS Policy"]["status"] == "Secure"
    assert result["CSP"]["status"] == "Secure"
    assert result["DNSSEC Zone Walking"]["status"] == "Secure"
    # Check that weak/vulnerable keys are NOT present
    assert "Subdomain Takeover" not in result
    assert "IP Reputation" not in result
    assert "Open Ports" not in result


def test_security_audit_weak(mock_weak_data):
    """
    Tests the security_audit function with data that should result in 'Weak' or
    'Vulnerable' statuses.
    """
    result = security_audit(**mock_weak_data)

    assert result["SPF Policy"]["status"] == "Weak"  # type: ignore
    assert result["DMARC Policy"]["status"] == "Weak"  # type: ignore
    assert (
        "Additionally, no 'rua' reporting address is configured"
        in result["DMARC Policy"]["details"]
    )
    assert result["CAA Record"]["status"] == "Weak"
    assert result["DNSSEC"]["status"] == "Weak"
    assert result["Zone Transfer"]["status"] == "Vulnerable"
    assert result["CSP"]["status"] == "Weak"
    assert result["SSL/TLS Certificate"]["status"] == "Weak"
    assert result["Subdomain Takeover"]["status"] == "Vulnerable"
    assert result["IP Blocklist Status"]["status"] == "Weak"
    assert result["Open Ports"]["status"] == "Weak"
    assert result["IP Reputation"]["status"] == "Weak"


def test_security_audit_moderate(mock_moderate_data):
    """
    Tests a specific case that should result in a 'Moderate' status.
    """
    result = security_audit(**mock_moderate_data)
    assert result["HSTS Policy"]["status"] == "Moderate"  # type: ignore
    assert "weak 'max-age'" in result["HSTS Policy"]["details"]


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
    assert "Joomla!" in result["technologies"]  # From meta tag
    assert "React" in result["technologies"]
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
    assert result["emails"] == "abuse@example.com, admin@example.com"  # type: ignore
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

    assert "WHOIS lookup failed: Domain not found." in result["error"]
