import pytest
import respx
from httpx import RequestError

from modules.analysis.ip_geolocation import geolocate_ips

IP_API_ENDPOINT = "http://ip-api.com/json/"


@pytest.mark.asyncio
@respx.mock
async def test_geolocate_ips_success():
    """
    Tests successful geolocation for a mix of A and AAAA records.
    """
    records_info = {
        "A": [{"value": "8.8.8.8"}],
        "AAAA": [{"value": "2606:4700:4700::1111"}],
        "MX": [{"value": "mail.example.com"}],  # Should be ignored
    }

    # Mock the API responses for the two IPs
    respx.get(
        f"{IP_API_ENDPOINT}8.8.8.8?fields=status,message,country,city,isp"
    ).respond(
        200,
        json={
            "status": "success",
            "country": "United States",
            "city": "Mountain View",
            "isp": "Google LLC",
        },
    )
    respx.get(
        f"{IP_API_ENDPOINT}2606:4700:4700::1111?fields=status,message,country,city,isp"
    ).respond(
        200,
        json={
            "status": "success",
            "country": "United States",
            "city": "San Francisco",
            "isp": "Cloudflare, Inc.",
        },
    )

    results = await geolocate_ips(records_info)

    assert "8.8.8.8" in results
    assert "2606:4700:4700::1111" in results
    assert results["8.8.8.8"]["country"] == "United States"
    assert results["8.8.8.8"]["isp"] == "Google LLC"
    assert "error" not in results["8.8.8.8"]

    assert results["2606:4700:4700::1111"]["city"] == "San Francisco"
    assert "error" not in results["2606:4700:4700::1111"]


@pytest.mark.asyncio
@respx.mock
async def test_geolocate_ips_api_failure():
    """
    Tests handling of a 'fail' status from the ip-api.com service.
    """
    records_info = {"A": [{"value": "127.0.0.1"}]}

    # Mock an API response indicating failure (e.g., for a private IP)
    respx.get(
        f"{IP_API_ENDPOINT}127.0.0.1?fields=status,message,country,city,isp"
    ).respond(200, json={"status": "fail", "message": "private range"})
    results = await geolocate_ips(records_info)  # type: ignore

    assert "127.0.0.1" in results
    assert "error" in results["127.0.0.1"]
    assert results["127.0.0.1"]["error"] == "private range"


@pytest.mark.asyncio
@respx.mock
async def test_geolocate_ips_request_error():
    """
    Tests handling of a network request exception (e.g., timeout).
    """
    records_info = {"A": [{"value": "10.0.0.1"}]}

    # Mock a network-level error
    url = f"{IP_API_ENDPOINT}10.0.0.1?fields=status,message,country,city,isp"
    respx.get(url).mock(side_effect=RequestError("Connection failed"))

    results = await geolocate_ips(records_info)

    assert "10.0.0.1" in results
    assert "error" in results["10.0.0.1"]
    assert "Request failed: RequestError" in results["10.0.0.1"]["error"]


@pytest.mark.asyncio
async def test_geolocate_ips_no_ip_records():
    """
    Tests that the function returns an empty dictionary when no A or AAAA records are provided.
    """
    records_info = {
        "MX": [{"value": "mail.example.com"}],
        "TXT": [{"value": "v=spf1 -all"}],
    }

    results = await geolocate_ips(records_info)

    assert results == {}
