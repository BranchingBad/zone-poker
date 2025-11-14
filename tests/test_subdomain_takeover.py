import importlib.resources
import json
from unittest.mock import mock_open, patch

import pytest
import respx
from httpx import RequestError

from modules.analysis.subdomain_takeover import (
    _load_fingerprints,
    check_subdomain_takeover,
)

# Mock fingerprint data that reflects the new schema
MOCK_FINGERPRINTS = {
    "GitHub Pages": {
        "cname": ["github.io"],
        "fingerprints": ["There isn't a GitHub Pages site here."],
    },
    "Heroku": {"cname": ["herokuapp.com"], "fingerprints": ["no such app"]},
}


@pytest.mark.asyncio
@respx.mock
async def test_subdomain_takeover_found():
    """Test that a potential subdomain takeover is correctly identified."""
    # This happens when both the CNAME and fingerprint match.
    records = {
        "CNAME": [
            {"name": "vuln.example.com", "value": "user.github.io"},
            {"name": "safe.example.com", "value": "another.service.com"},
        ]
    }

    # Mock the vulnerable response for the first subdomain.
    # The new logic checks HTTP first, so we only need to mock that.
    fingerprint = MOCK_FINGERPRINTS["GitHub Pages"]["fingerprints"]  # type: ignore
    respx.get("http://vuln.example.com").respond(200, text=f"<html><body>{fingerprint}</body></html>")
    respx.get("http://safe.example.com").respond(200, text="Everything is fine here.")

    # Use patch to inject our mock fingerprints and clear the cache
    with patch(
        "modules.analysis.subdomain_takeover._load_fingerprints",
        return_value=MOCK_FINGERPRINTS,
    ):
        _load_fingerprints.cache_clear()
        results = await check_subdomain_takeover(records)

    assert len(results["vulnerable"]) == 1
    vulnerability = results["vulnerable"][0]
    assert vulnerability["subdomain"] == "vuln.example.com"
    assert vulnerability["service"] == "GitHub Pages"
    assert vulnerability["cname_target"] == "user.github.io"
    assert vulnerability["protocol"] == "http"


@pytest.mark.asyncio
@respx.mock
async def test_subdomain_takeover_not_found():
    """Test that no takeover is reported when CNAME matches but fingerprint does not."""
    records = {"CNAME": [{"name": "safe.example.com", "value": "user.github.io"}]}
    # Mock a response that does NOT contain the fingerprint
    respx.get(url__regex=r"https?://safe\.example\.com").respond(200, text="OK")

    with patch(
        "modules.analysis.subdomain_takeover._load_fingerprints",
        return_value=MOCK_FINGERPRINTS,
    ):
        _load_fingerprints.cache_clear()
        results = await check_subdomain_takeover(records)

    assert len(results["vulnerable"]) == 0


@pytest.mark.asyncio
async def test_subdomain_takeover_no_cnames():  # noqa E302
    """Test that the function returns empty results when no CNAME records are provided."""
    records = {"A": [{"name": "example.com", "value": "1.2.3.4"}]}
    results = await check_subdomain_takeover(records)
    assert len(results["vulnerable"]) == 0


@pytest.mark.asyncio
@respx.mock
async def test_subdomain_takeover_network_error():
    """Test that a network error during the HTTP check is handled gracefully."""
    records = {"CNAME": [{"name": "error.example.com", "value": "user.github.io"}]}

    # Mock a network error for the target URL
    respx.get(url__regex=r"https?://error\.example\.com").mock(side_effect=RequestError("Connection failed"))

    results = await check_subdomain_takeover(records)

    # Ensure no vulnerability was reported
    assert len(results["vulnerable"]) == 0


@pytest.mark.asyncio
@respx.mock
async def test_subdomain_takeover_missing_keys():
    """Test that CNAME records missing 'name' or 'value' keys are handled gracefully."""
    records = {
        "CNAME": [
            {"value": "some.service.com"},  # Missing 'name'
            {"name": "another.example.com"},  # Missing 'value'
            {"name": "vuln.example.com", "value": "user.github.io"},
        ]
    }

    # Mock the vulnerable response for the valid CNAME record
    github_fingerprint = MOCK_FINGERPRINTS["GitHub Pages"]["fingerprints"][0]
    respx.get("http://vuln.example.com").respond(200, text=github_fingerprint)

    with patch(
        "modules.analysis.subdomain_takeover._load_fingerprints",
        return_value=MOCK_FINGERPRINTS,
    ):
        _load_fingerprints.cache_clear()
        results = await check_subdomain_takeover(records)

    # The function should ignore the malformed record and find the valid one.
    assert len(results["vulnerable"]) == 1
    assert results["vulnerable"][0]["subdomain"] == "vuln.example.com"


@pytest.mark.asyncio
async def test_fingerprint_caching():
    """Test that the fingerprint JSON file is only read once due to lru_cache."""
    mock_file_content = json.dumps(MOCK_FINGERPRINTS)
    m = mock_open(read_data=mock_file_content)

    # Clear the cache before the test to ensure a clean state
    _load_fingerprints.cache_clear()

    with patch("builtins.open", m):
        # First call should read the file
        first_call_result = _load_fingerprints()
        m.assert_called_once()
        assert first_call_result == MOCK_FINGERPRINTS

        # Second call should hit the cache and not open the file again
        second_call_result = _load_fingerprints()
        m.assert_called_once()  # Still only called once
        assert second_call_result == MOCK_FINGERPRINTS


def test_fingerprints_file_is_packaged():
    """Tests that the takeover_fingerprints.json file is correctly included in the package data."""
    # It tries to read it from the installed package resources.
    # This test is particularly useful when run against an installed wheel.
    try:
        # importlib.resources.files() is the modern way to access package data
        # and will correctly find the file in the installed package.
        # This will raise an exception if the file is not found.
        with importlib.resources.files("modules.analysis").joinpath("takeover_fingerprints.json").open("r") as f:
            data = json.load(f)
            # A simple assertion to ensure the file content is as expected
            assert "GitHub Pages" in data
            assert "Heroku" in data
    except FileNotFoundError:
        pytest.fail(
            "takeover_fingerprints.json was not found. " "Check that it is included in pyproject.toml's [tool.setuptools.package-data]."
        )
