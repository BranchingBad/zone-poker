import pytest
import respx
from httpx import RequestError

from modules.analysis.subdomain_takeover import check_subdomain_takeover, TAKEOVER_FINGERPRINTS


@pytest.mark.asyncio
@respx.mock
async def test_subdomain_takeover_found():
    """
    Test that a potential subdomain takeover is correctly identified.
    """
    records = {
        "CNAME": [
            {"name": "vuln.example.com", "value": "pages.github.com"},
            {"name": "safe.example.com", "value": "another.service.com"},
        ]
    }

    # Mock the vulnerable response for the first subdomain (checking both http/https)
    github_fingerprint = TAKEOVER_FINGERPRINTS["GitHub Pages"]
    respx.get("http://vuln.example.com").respond(200, text=github_fingerprint)
    respx.get("https://vuln.example.com").respond(200, text=github_fingerprint)

    # Mock a safe response for the second subdomain
    respx.get("http://safe.example.com").respond(200, text="Everything is fine here.")
    respx.get("https://safe.example.com").respond(200, text="Everything is fine here.")

    results = await check_subdomain_takeover(records)

    assert len(results["vulnerable"]) == 1
    vulnerability = results["vulnerable"][0]
    assert vulnerability["subdomain"] == "vuln.example.com"
    assert vulnerability["service"] == "GitHub Pages"
    assert vulnerability["cname_target"] == "pages.github.com"


@pytest.mark.asyncio
@respx.mock
async def test_subdomain_takeover_not_found():
    """
    Test that no takeover is reported when fingerprints are not present.
    """
    records = {"CNAME": [{"name": "safe.example.com", "value": "some.service.com"}]}

    respx.get(url__regex=r"https?://safe\.example\.com").respond(200, text="OK")

    results = await check_subdomain_takeover(records)

    assert len(results["vulnerable"]) == 0


@pytest.mark.asyncio
async def test_subdomain_takeover_no_cnames():
    """
    Test that the function returns empty results when no CNAME records are provided.
    """
    records = {"A": [{"name": "example.com", "value": "1.2.3.4"}]}
    results = await check_subdomain_takeover(records)
    assert len(results["vulnerable"]) == 0


@pytest.mark.asyncio
@respx.mock
async def test_subdomain_takeover_network_error(caplog):
    """
    Test that a network error is handled gracefully and logged.
    """
    records = {"CNAME": [{"name": "error.example.com", "value": "service.com"}]}

    # Mock a network error for the target URL
    respx.get(url__regex=r"https?://error\.example\.com").mock(side_effect=RequestError("Connection failed"))

    results = await check_subdomain_takeover(records)

    # Ensure no vulnerability was reported
    assert len(results["vulnerable"]) == 0
    # Check that the error was logged at the debug level
    assert "Subdomain takeover check for http://error.example.com failed: Connection failed" in caplog.text


@pytest.mark.asyncio
@respx.mock
async def test_subdomain_takeover_missing_name_key():
    """
    Test that a CNAME record missing the 'name' key is handled gracefully.
    This verifies the fix for inconsistent data from the dns_records module.
    """
    records = {
        "CNAME": [
            {"value": "some.service.com"},  # This record is missing the 'name' key
            {"name": "vuln.example.com", "value": "pages.github.com"},
        ]
    }

    # Mock the vulnerable response for the valid CNAME record
    github_fingerprint = TAKEOVER_FINGERPRINTS["GitHub Pages"]
    respx.get("http://vuln.example.com").respond(200, text=github_fingerprint)

    results = await check_subdomain_takeover(records)

    # The function should ignore the malformed record and find the valid one.
    assert len(results["vulnerable"]) == 1
    assert results["vulnerable"][0]["subdomain"] == "vuln.example.com"