import pytest
import respx
from httpx import Response, RequestError
import argparse

from modules.analysis.reputation import analyze_reputation, ABUSEIPDB_ENDPOINT


@pytest.fixture
def mock_args():
    """Creates a mock argparse.Namespace object with an API key."""
    args = argparse.Namespace()
    args.timeout = 10
    args.api_keys = {"abuseipdb": "test_api_key"}
    return args


@pytest.fixture
def mock_args_no_key():
    """Creates a mock argparse.Namespace object without an API key."""
    args = argparse.Namespace()
    args.timeout = 10
    args.api_keys = {}
    return args


@pytest.mark.asyncio
@respx.mock
async def test_analyze_reputation_success(mock_args):
    """
    Test successful reputation analysis for given IP addresses.
    """
    domain = "example.com"
    records = {"A": [{"value": "1.1.1.1"}], "AAAA": [{"value": "2606:4700:4700::1111"}]}

    # Mock AbuseIPDB API responses
    respx.get(url=f"{ABUSEIPDB_ENDPOINT}?ipAddress=1.1.1.1&maxAgeInDays=90").respond(
        200, json={"data": {"ipAddress": "1.1.1.1", "abuseConfidenceScore": 0}}
    )
    respx.get(
        url=f"{ABUSEIPDB_ENDPOINT}?ipAddress=2606%3A4700%3A4700%3A%3A1111&maxAgeInDays=90"
    ).respond(
        200,
        json={
            "data": {"ipAddress": "2606:4700:4700::1111", "abuseConfidenceScore": 90}
        },
    )

    results = await analyze_reputation(domain, mock_args, records)

    assert "1.1.1.1" in results
    assert "2606:4700:4700::1111" in results
    assert results["1.1.1.1"]["abuseConfidenceScore"] == 0
    assert results["2606:4700:4700::1111"]["abuseConfidenceScore"] == 90


@pytest.mark.asyncio
async def test_analyze_reputation_no_api_key(mock_args_no_key):
    """
    Test that the function returns an error if no API key is provided.
    """
    domain = "example.com"
    records = {"A": [{"value": "1.1.1.1"}]}

    results = await analyze_reputation(domain, mock_args_no_key, records)

    assert "error" in results
    assert results["error"] == "AbuseIPDB API key not found in config file."


@pytest.mark.asyncio
async def test_analyze_reputation_no_ip_records(mock_args):
    """
    Test that the function returns an error if no A or AAAA records are found.
    """
    domain = "example.com"
    records = {"MX": [{"value": "mail.example.com"}]}

    results = await analyze_reputation(domain, mock_args, records)

    assert "error" in results
    assert results["error"] == "No A or AAAA records found to check reputation."


@pytest.mark.asyncio
@respx.mock
async def test_analyze_reputation_auth_error(mock_args):
    """
    Test handling of an authentication error (401) from the API.
    """
    domain = "example.com"
    records = {"A": [{"value": "1.1.1.1"}]}

    # Mock a 401 Unauthorized response
    respx.get(url__regex=r".*").respond(
        401, json={"errors": [{"detail": "Authentication failed"}]}
    )

    results = await analyze_reputation(domain, mock_args, records)

    assert "1.1.1.1" in results
    assert "error" in results["1.1.1.1"]
    assert "Authentication failed" in results["1.1.1.1"]["error"]


@pytest.mark.asyncio
@respx.mock
async def test_analyze_reputation_network_error(mock_args):
    """
    Test handling of a network request error.
    """
    domain = "example.com"
    records = {"A": [{"value": "1.1.1.1"}]}

    # Mock a network error
    respx.get(url__regex=r".*").mock(side_effect=RequestError("Connection timeout"))

    results = await analyze_reputation(domain, mock_args, records)

    assert "1.1.1.1" in results
    assert "error" in results["1.1.1.1"]
    assert "Connection error" in results["1.1.1.1"]["error"]
