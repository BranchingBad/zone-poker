#!/usr/bin/env python3
"""
Unit tests for the Cloud Enumeration module in Zone-Poker.
"""

import re

import pytest
import respx
from httpx import RequestError

from modules.analysis.cloud_enum import enumerate_cloud_services


@pytest.mark.asyncio
@respx.mock
async def test_enumerate_cloud_services_found():
    """
    Tests that enumerate_cloud_services correctly identifies S3 buckets and Azure blobs
    with various statuses and handles permutations correctly for a .ca domain.
    """
    domain = "example.ca"

    # Mock only the responses that should NOT be 404
    respx.head("http://example.s3.amazonaws.com").respond(200)
    respx.head("http://example-assets.s3.amazonaws.com").respond(403)
    respx.head("http://example.ca.s3.amazonaws.com").respond(200)
    respx.head("http://exampleca.s3.amazonaws.com").respond(403)
    respx.head("https://example.blob.core.windows.net").respond(400)
    respx.head("https://exampleca.blob.core.windows.net").respond(400)
    respx.head("https://exampledev.blob.core.windows.net").mock(side_effect=RequestError("Connection failed"))

    # Add a catch-all for any other S3 or Azure URLs to return 404.
    # This makes the test robust against changes in permutation logic.
    s3_regex = re.compile(r"https?://.*\.s3\.amazonaws\.com.*")
    azure_regex = re.compile(r"https?://.*\.blob\.core\.windows\.net.*")
    respx.head(url=s3_regex).respond(404)
    respx.head(url=azure_regex).respond(404)

    result = await enumerate_cloud_services(domain=domain)

    # --- Assert S3 Results ---
    assert len(result["s3_buckets"]) == 4
    s3_urls = {b["url"] for b in result["s3_buckets"]}
    assert "http://example.s3.amazonaws.com" in s3_urls
    assert "http://example-assets.s3.amazonaws.com" in s3_urls
    assert "http://exampleca.s3.amazonaws.com" in s3_urls

    # Check statuses (results are sorted by URL)
    assert result["s3_buckets"][0]["url"] == "http://example-assets.s3.amazonaws.com"
    assert result["s3_buckets"][0]["status"] == "forbidden"

    assert result["s3_buckets"][1]["url"] == "http://example.ca.s3.amazonaws.com"
    assert result["s3_buckets"][1]["status"] == "public"

    assert result["s3_buckets"][2]["url"] == "http://example.s3.amazonaws.com"
    assert result["s3_buckets"][2]["status"] == "public"

    assert result["s3_buckets"][3]["url"] == "http://exampleca.s3.amazonaws.com"
    assert result["s3_buckets"][3]["status"] == "forbidden"
    assert len(result["azure_blobs"]) == 2
    azure_urls = {b["url"] for b in result["azure_blobs"]}
    assert "https://example.blob.core.windows.net" in azure_urls
    assert "https://exampleca.blob.core.windows.net" in azure_urls

    # Check statuses (results are sorted by URL)
    assert result["azure_blobs"][0]["url"] == "https://example.blob.core.windows.net"
    assert result["azure_blobs"][0]["status"] == "valid_account"
    assert result["azure_blobs"][1]["url"] == "https://exampleca.blob.core.windows.net"
    assert result["azure_blobs"][1]["status"] == "valid_account"


@pytest.mark.asyncio
@respx.mock
async def test_enumerate_cloud_services_none_found():
    """
    Tests that the function returns empty lists when no cloud services are found.
    """
    domain = "notfound.com"

    # For this test, we expect everything to be a 404, so we can just use
    # the catch-all routes.
    s3_regex = re.compile(r"https?://.*\.s3\.amazonaws\.com.*")
    azure_regex = re.compile(r"https?://.*\.blob\.core\.windows\.net.*")
    respx.head(url=s3_regex).respond(404)
    respx.head(url=azure_regex).respond(404)

    result = await enumerate_cloud_services(domain=domain)

    assert result["s3_buckets"] == []
    assert result["azure_blobs"] == []


@pytest.mark.asyncio
@respx.mock
async def test_enumerate_cloud_services_invalid_azure_name():
    """Tests that invalid Azure names (e.g., too short) are skipped."""
    # This test doesn't require mocking because the invalid name `ex`
    # should be filtered out. However, permutations like 'exdev' are valid.
    domain = "ex.com"

    # We expect all valid permutations to be checked and return 404.
    # The function under test should not even attempt to check invalid Azure
    # names like "ex", so we don't need to mock them.
    s3_regex = re.compile(r"https?://.*\.s3\.amazonaws\.com.*")
    azure_regex = re.compile(r"https?://.*\.blob\.core\.windows\.net.*")
    respx.head(url=s3_regex).respond(404)
    respx.head(url=azure_regex).respond(404)

    result = await enumerate_cloud_services(domain=domain)
    assert not result["azure_blobs"]
