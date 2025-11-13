import pytest
import respx
from httpx import RequestError

from modules.analysis.ip_geolocation import geolocate_ips

IP_API_BATCH_ENDPOINT = "http://ip-api.com/batch"


@pytest.mark.asyncio
@respx.mock
async def test_geolocate_ips_success():
    """
    Tests successful geolocation for a mix of A and AAAA records.
    """
    records_info = {
        "records_info": {
            "A": [{"value": "8.8.8.8"}],
            "AAAA": [{"value": "2606:4700:4700::1111"}],
            "MX": [{"value": "mail.example.com"}],  # Should be ignored
        }
    }

    # Mock the batch API response for the two IPs
    mock_response_data = [
        {
            "query": "8.8.8.8",
            "status": "success",
            "country": "United States",
            "city": "Mountain View",
            "isp": "Google LLC",
        },
        {
            "query": "2606:4700:4700::1111",
            "status": "success",
            "country": "United States",
            "city": "San Francisco",
            "isp": "Cloudflare, Inc.",
        },
    ]
    url = f"{IP_API_BATCH_ENDPOINT}?fields=status,message,country,city,isp,query"
    respx.post(url).respond(200, json=mock_response_data)

    results = await geolocate_ips(records_info)

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
    records_info = {"records_info": {"A": [{"value": "127.0.0.1"}]}}

    # Mock an API response indicating failure (e.g., for a private IP)
    mock_response_data = [
        {"query": "127.0.0.1", "status": "fail", "message": "private range"}
    ]
    url = f"{IP_API_BATCH_ENDPOINT}?fields=status,message,country,city,isp,query"
    respx.post(url).respond(200, json=mock_response_data)

    results = await geolocate_ips(records_info)

    assert "127.0.0.1" in results
    assert "error" in results["127.0.0.1"]
    assert results["127.0.0.1"]["error"] == "private range"


@pytest.mark.asyncio
@respx.mock
async def test_geolocate_ips_request_error():
    """
    Tests handling of a network request exception (e.g., timeout).
    """
    records_info = {"records_info": {"A": [{"value": "10.0.0.1"}]}}

    # Mock a network-level error
    url = f"{IP_API_BATCH_ENDPOINT}?fields=status,message,country,city,isp,query"
    respx.post(url).mock(side_effect=RequestError("Connection failed"))

    results = await geolocate_ips(records_info)

    assert "10.0.0.1" in results
    assert "error" in results["10.0.0.1"]
    assert "Batch request failed: RequestError" in results["10.0.0.1"]["error"]


@pytest.mark.asyncio
async def test_geolocate_ips_no_ip_records():
    """
    Tests that the function returns an empty dictionary when no A or AAAA records are provided.
    """
    records_info = {
        "records_info": {
            "MX": [{"value": "mail.example.com"}],
            "TXT": [{"value": "v=spf1 -all"}],
        }
    }

    results = await geolocate_ips(records_info)

    assert results == {}


@pytest.mark.asyncio
@respx.mock
async def test_geolocate_ips_batching():
    """
    Tests that IP geolocation correctly uses the batch endpoint when more than 100 IPs are provided.
    """
    # 1. Generate 102 unique IPs
    ips = [f"1.1.1.{i}" for i in range(102)]
    all_data = {"records_info": {"A": [{"value": ip} for ip in ips]}}

    # 2. Define the mock responses for two batches
    batch1_ips = ips[:100]
    batch2_ips = ips[100:]

    batch1_response = [
        {
            "query": ip,
            "status": "success",
            "country": "Testland",
            "city": "Batch 1",
            "isp": "Test ISP",
        }
        for ip in batch1_ips
    ]
    batch2_response = [
        {
            "query": ip,
            "status": "success",
            "country": "Testland",
            "city": "Batch 2",
            "isp": "Test ISP",
        }
        for ip in batch2_ips
    ]

    # 3. Mock the two consecutive POST requests to the batch endpoint
    url = f"{IP_API_BATCH_ENDPOINT}?fields=status,message,country,city,isp,query"
    respx.post(url).respond(200, json=batch1_response)
    respx.post(url).respond(200, json=batch2_response)

    # 4. Run the function and assert the results
    results = await geolocate_ips(all_data)

    assert len(results) == 102
    assert results["1.1.1.99"]["city"] == "Batch 1"
    assert results["1.1.1.101"]["city"] == "Batch 2"


@pytest.mark.asyncio
@respx.mock
async def test_geolocate_ip_from_headers():
    """
    Tests that the IP address from the http_headers analysis is correctly geolocated.
    """
    all_data = {
        "records_info": {"A": [{"value": "8.8.8.8"}]},
        "headers_info": {"ip_address": "1.1.1.1"},
    }

    mock_response_data = [
        {"query": "8.8.8.8", "status": "success", "country": "USA", "isp": "Google"},
        {
            "query": "1.1.1.1",
            "status": "success",
            "country": "Australia",
            "isp": "Cloudflare",
        },
    ]
    url = f"{IP_API_BATCH_ENDPOINT}?fields=status,message,country,city,isp,query"
    respx.post(url).respond(200, json=mock_response_data)

    results = await geolocate_ips(all_data)

    # Check that both the IP from DNS records and the IP from headers were geolocated
    assert len(results) == 2
    assert "8.8.8.8" in results
    assert "1.1.1.1" in results
    assert results["1.1.1.1"]["country"] == "Australia"
    assert results["8.8.8.8"]["isp"] == "Google"
