import argparse

import pytest
import respx
from httpx import RequestError

from modules.analysis.reputation import ABUSEIPDB_ENDPOINT, analyze_reputation


@pytest.fixture
def mock_args(request):
    """Creates a mock argparse.Namespace object."""  # noqa
    # Can be parameterized to include or exclude the API key.
    # e.g. @pytest.mark.parametrize("mock_args", [{"api_keys": {"abuseipdb": "test_key"}}], indirect=True)
    args = argparse.Namespace()
    args.timeout = 10
    # Use request.param if it exists, otherwise default to an empty dict
    args.api_keys = getattr(request, "param", {}).get("api_keys", {})
    return args


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("mock_args", [{"api_keys": {"abuseipdb": "test_api_key"}}], indirect=True)
async def test_analyze_reputation_success(mock_args):
    """Test successful reputation analysis for given IP addresses."""  # noqa
    domain = "example.com"
    # Note: 8.8.8.8 is intentionally duplicated to test for uniqueness
    all_data = {
        "records_info": {
            "A": [{"value": "1.1.1.1"}],
            "AAAA": [{"value": "2606:4700:4700::1111"}],
            "MX": [{"value": "8.8.8.8"}],  # Assuming an IP could be in an MX record value
        },
        "headers_info": {"ip_address": "8.8.8.8"},  # Also check header IP
    }

    # Mock AbuseIPDB API responses
    respx.get(url=f"{ABUSEIPDB_ENDPOINT}?ipAddress=1.1.1.1&maxAgeInDays=90").respond(
        200, json={"data": {"ipAddress": "1.1.1.1", "abuseConfidenceScore": 0}}
    )
    respx.get(url=f"{ABUSEIPDB_ENDPOINT}?ipAddress=2606%3A4700%3A4700%3A%3A1111&maxAgeInDays=90").respond(
        200,
        json={"data": {"ipAddress": "2606:4700:4700::1111", "abuseConfidenceScore": 90}},
    )
    respx.get(url=f"{ABUSEIPDB_ENDPOINT}?ipAddress=8.8.8.8&maxAgeInDays=90").respond(
        200, json={"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 5}}
    )

    results = await analyze_reputation(domain=domain, args=mock_args, all_data=all_data)

    assert "1.1.1.1" in results
    assert "2606:4700:4700::1111" in results
    assert "8.8.8.8" in results
    assert results["1.1.1.1"]["abuseConfidenceScore"] == 0
    assert results["2606:4700:4700::1111"]["abuseConfidenceScore"] == 90
    assert results["8.8.8.8"]["abuseConfidenceScore"] == 5
    assert len(respx.calls) == 3  # Verifies that the duplicate IP was only queried once


@pytest.mark.asyncio
async def test_analyze_reputation_no_api_key(mock_args):
    """Test that the function returns an error if no API key is provided."""  # noqa
    domain = "example.com"
    all_data = {"records_info": {"A": [{"value": "1.1.1.1"}]}}

    # This test uses the default mock_args fixture which has no API keys.
    results = await analyze_reputation(domain=domain, args=mock_args, all_data=all_data)

    assert "error" in results
    assert results["error"] == "AbuseIPDB API key not found in config file."


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_args", [{"api_keys": {"abuseipdb": "test_api_key"}}], indirect=True)
async def test_analyze_reputation_no_ip_records(mock_args):
    """Test that the function returns an error if no A or AAAA records are found."""  # noqa
    domain = "example.com"
    all_data = {"records_info": {"MX": [{"value": "mail.example.com"}]}}

    results = await analyze_reputation(domain=domain, args=mock_args, all_data=all_data)

    assert "error" in results
    assert results["error"] == "No A or AAAA records found to check reputation."


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("mock_args", [{"api_keys": {"abuseipdb": "test_api_key"}}], indirect=True)
async def test_analyze_reputation_auth_error(mock_args):
    """Test handling of an authentication error (401) from the API."""  # noqa
    domain = "example.com"
    all_data = {"records_info": {"A": [{"value": "1.1.1.1"}]}}

    # Mock a 401 Unauthorized response
    respx.get(url__regex=r".*").respond(401, json={"errors": [{"detail": "Authentication failed"}]})

    results = await analyze_reputation(domain=domain, args=mock_args, all_data=all_data)

    assert "1.1.1.1" in results
    assert "error" in results["1.1.1.1"]
    assert "Authentication failed (invalid API key)" in results["1.1.1.1"]["error"]


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("mock_args", [{"api_keys": {"abuseipdb": "test_api_key"}}], indirect=True)
async def test_analyze_reputation_network_error(mock_args):
    """Test handling of a network request error."""  # noqa
    domain = "example.com"
    all_data = {"records_info": {"A": [{"value": "1.1.1.1"}]}}

    # Mock a network error
    respx.get(url__regex=r".*").mock(side_effect=RequestError("Connection timeout"))

    results = await analyze_reputation(domain=domain, args=mock_args, all_data=all_data)

    assert "1.1.1.1" in results
    assert "error" in results["1.1.1.1"]
    assert "Connection error: Connection timeout" in results["1.1.1.1"]["error"]


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("mock_args", [{"api_keys": {"abuseipdb": "test_api_key"}}], indirect=True)
async def test_analyze_reputation_rate_limit_error(mock_args):
    """Test handling of a rate limit error (429) from the API."""  # noqa
    domain = "example.com"
    all_data = {"records_info": {"A": [{"value": "1.1.1.1"}]}}

    # Mock a 429 Too Many Requests response
    respx.get(url__regex=r".*").respond(429, json={"errors": [{"detail": "API rate limit exceeded"}]})

    results = await analyze_reputation(domain=domain, args=mock_args, all_data=all_data)

    assert "1.1.1.1" in results
    assert "error" in results["1.1.1.1"]
    assert "API rate limit exceeded" in results["1.1.1.1"]["error"]
