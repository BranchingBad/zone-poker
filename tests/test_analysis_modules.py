#!/usr/bin/env python3
"""
Unit tests for the analysis modules in Zone-Poker.
"""
import pytest
import respx
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
from whois.parser import PywhoisError
from modules.analysis.security_audit import security_audit
from modules.analysis.tech import detect_technologies
from modules.analysis.whois import whois_lookup

# --- Test Data Fixtures ---

@pytest.fixture
def mock_secure_data():
    """Provides mock data representing a secure configuration."""
    return {
        "records": {"CAA": [{"value": "0 issue 'letsencrypt.org'"}]},
        "email_security": {
            "spf": {"all_policy": "-all"},
            "dmarc": {"p": "reject", "rua": "mailto:dmarc@example.com"}
        },
        "ns_info": {"dnssec": "Enabled (DNSKEY and DS records found)"},
        "zone_info": {"summary": "Secure (No successful transfers)"}
    }

@pytest.fixture
def mock_weak_data():
    """Provides mock data representing a weak or misconfigured setup."""
    return {
        "records": {}, # No CAA record
        "email_security": {
            "spf": {"all_policy": "?all"},
            "dmarc": {"p": "none"} # No rua address
        },
        "ns_info": {"dnssec": "Not Enabled (No DNSKEY or DS records)"},
        "zone_info": {"summary": "Vulnerable (Zone Transfer Successful)"}
    }

# --- Test Functions ---

def test_security_audit_secure(mock_secure_data):
    """
    Tests the security_audit function with data that should result in all 'Secure' statuses.
    """
    result = security_audit(**mock_secure_data)

    assert result["SPF Policy"]["status"] == "Secure"
    assert result["DMARC Policy"]["status"] == "Secure"
    assert result["CAA Record"]["status"] == "Secure"
    assert result["DNSSEC"]["status"] == "Secure"
    assert result["Zone Transfer"]["status"] == "Secure"

def test_security_audit_weak(mock_weak_data):
    """
    Tests the security_audit function with data that should result in 'Weak' or 'Vulnerable' statuses.
    """
    result = security_audit(**mock_weak_data)

    assert result["SPF Policy"]["status"] == "Weak"
    assert result["DMARC Policy"]["status"] == "Weak"
    assert "Additionally, no 'rua' reporting address is configured" in result["DMARC Policy"]["details"]
    assert result["CAA Record"]["status"] == "Weak"
    assert result["DNSSEC"]["status"] == "Weak"
    assert result["Zone Transfer"]["status"] == "Vulnerable"

@pytest.mark.asyncio
@respx.mock
async def test_detect_technologies_found():
    """
    Tests that detect_technologies correctly identifies technologies from headers,
    HTML content, and script tags.
    """
    domain = "tech-example.com"
    url = f"https://{domain}"
    
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
    respx.get(url).respond(200, headers=mock_headers, html=mock_html)

    result = await detect_technologies(domain=domain, timeout=5, verbose=False)

    assert "WordPress" in result["technologies"]
    assert "Joomla!" in result["technologies"]  # From meta tag
    assert "React" in result["technologies"]
    assert "PHP" in result["technologies"]  # From fingerprint on X-Powered-By header

@pytest.mark.asyncio
async def test_whois_lookup_success():
    """
    Tests a successful whois_lookup, including data normalization of lists and datetimes.
    """
    mock_whois_data = MagicMock()
    mock_whois_data.text = "raw whois text"
    # Simulate the data structure returned by the python-whois library
    mock_whois_data.items.return_value = [
        ("domain_name", ["EXAMPLE.COM"]),
        ("creation_date", datetime(2020, 1, 1)),
        ("registrar", "Test Registrar"),
        ("emails", ["abuse@example.com", "admin@example.com"])
    ]

    with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.return_value = mock_whois_data
        result = await whois_lookup(domain="example.com", verbose=False)

    assert result["domain_name"] == "EXAMPLE.COM"
    assert result["creation_date"] == "2020-01-01T00:00:00"
    assert result["registrar"] == "Test Registrar"
    assert result["emails"] == "abuse@example.com"  # Check that only the first email is taken
    assert "error" not in result

@pytest.mark.asyncio
async def test_whois_lookup_no_data_returned():
    """
    Tests the case where the whois query runs but returns an empty result.
    """
    mock_whois_data = MagicMock()
    mock_whois_data.text = "" # The check for success is based on the .text attribute
    with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.return_value = mock_whois_data
        result = await whois_lookup(domain="example.com", verbose=False)

    assert result["error"] == "No WHOIS data returned from server."

@pytest.mark.asyncio
async def test_whois_lookup_pywhois_error():
    """
    Tests the handling of a PywhoisError, which typically occurs for non-existent domains.
    """
    with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = PywhoisError("Domain not found.")
        result = await whois_lookup(domain="nonexistent.com", verbose=False)

    assert "WHOIS lookup failed: Domain not found." in result["error"]