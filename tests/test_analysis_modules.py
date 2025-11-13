#!/usr/bin/env python3
"""
Unit tests for the analysis modules in Zone-Poker.
"""
import pytest
import respx
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import RequestError
from datetime import datetime

from modules.analysis.tech import detect_technologies
from modules.analysis.whois import whois_lookup
from modules.analysis.critical_findings import aggregate_critical_findings
from modules.analysis.ct_logs import search_ct_logs
from modules.analysis.open_redirect import check_open_redirect


@pytest.fixture
def mock_secure_data():
    """Provides mock data representing a secure configuration."""
    # This fixture is now only used for critical_findings test
    return {}


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

    # Define the outcome for the vulnerable payload
    outcomes = {
        vulnerable_payload: {
            "status": 302,
            "location": "https://example.com/malicious",
        }
    }
    setup_open_redirect_mocks(domain, outcomes)

    result = await check_open_redirect(domain=domain, timeout=5)

    assert len(result["vulnerable_urls"]) == 1
    finding = result["vulnerable_urls"][0]
    assert finding["url"] == f"https://{domain}{vulnerable_payload}"
    assert finding["redirects_to"] == "https://example.com/malicious"


@pytest.mark.asyncio
@respx.mock
async def test_check_open_redirect_not_vulnerable():
    """
    Tests that check_open_redirect handles non-vulnerable cases correctly,
    including safe redirects and network errors.
    """
    domain = "safe-site.com"
    # Define outcomes for various non-vulnerable scenarios
    outcomes = {
        # Safe internal redirect
        "/?next=https://example.com": {"status": 302, "location": "/dashboard"},
        # Normal 200 OK
        "//example.com": 200,
        # Network error
        "/login?redirect=https://example.com": RequestError("Connection failed"),
    }
    setup_open_redirect_mocks(domain, outcomes)

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


def setup_open_redirect_mocks(domain: str, outcomes: dict):
    """
    Helper to set up respx mocks for open redirect tests in a declarative way.

    Args:
        domain: The domain under test.
        outcomes: A dictionary mapping URL payloads to their mocked outcomes.
                  The outcome can be a status code (int) or a dictionary
                  for redirects, e.g., {"status": 302, "location": "/dashboard"}.
    """
    # Mock specific outcomes
    for payload, outcome in outcomes.items():
        url = f"https://{domain}{payload}"

        if isinstance(outcome, int):
            respx.get(url).respond(outcome)
        elif isinstance(outcome, dict):
            respx.get(url).respond(
                outcome["status"], headers={"Location": outcome["location"]}
            )
        elif isinstance(outcome, Exception):
            respx.get(url).mock(side_effect=outcome)

    # Add a catch-all for any other payloads that might be tested by the module
    # but are not relevant to this specific test case.
    respx.get(url__regex=f"https?://{domain}/.*").respond(200)


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
