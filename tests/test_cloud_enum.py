#!/usr/bin/env python3
"""
Unit tests for the Cloud Enumeration module in Zone-Poker.
"""
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

    # --- Mock S3 Responses ---
    # Public bucket
    respx.head("http://example.s3.amazonaws.com").respond(200)
    # Forbidden bucket
    respx.head("http://example-assets.s3.amazonaws.com").respond(403)
    # Non-existent bucket (should be ignored)
    respx.head("http://example-prod.s3.amazonaws.com").respond(404)
    # Bucket from the domain with TLD (e.g., example.ca)
    respx.head("http://example.ca.s3.amazonaws.com").respond(200)
    # Bucket from the domain without dots (e.g., exampleca)
    respx.head("http://exampleca.s3.amazonaws.com").respond(403)
    respx.head("http://example-dev.s3.amazonaws.com").respond(404)
    respx.head("http://example-media.s3.amazonaws.com").respond(404)
    respx.head("http://example-www.s3.amazonaws.com").respond(404)
    respx.head("http://example-backups.s3.amazonaws.com").respond(404)

    # --- Mock Azure Responses ---
    # Forbidden blob (valid account)
    respx.head("https://example.blob.core.windows.net").respond(400)
    # Non-existent blob (should be ignored)
    respx.head("https://exampleassets.blob.core.windows.net").respond(404)
    # Blob from domain without dots
    respx.head("https://exampleca.blob.core.windows.net").respond(400)
    # A permutation that results in a network error
    respx.head("https://exampledev.blob.core.windows.net").mock(
        side_effect=RequestError("Connection failed")
    )
    respx.head("https://examplebackups.blob.core.windows.net/").respond(404)
    # Add mocks for other permutations that are now being checked
    respx.head("https://examplemedia.blob.core.windows.net/").respond(404)
    respx.head("https://exampleprod.blob.core.windows.net/").respond(404)
    respx.head("https://examplewww.blob.core.windows.net/").mock(
        side_effect=RequestError("Connection failed")
    )

    # All other permutations will implicitly return 404 and be ignored.

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

    # Mock all potential permutations to return 404
    # respx by default returns 404 for any unmatched routes, so we don't need
    # to explicitly mock them all.
    respx.head("http://notfound.s3.amazonaws.com").respond(404)
    respx.head("http://notfound-assets.s3.amazonaws.com").respond(404)
    respx.head("http://notfound-dev.s3.amazonaws.com").respond(404)
    respx.head("http://notfound-media.s3.amazonaws.com").respond(404)
    respx.head("http://notfound-prod.s3.amazonaws.com").respond(404)
    respx.head("http://notfound.com.s3.amazonaws.com").respond(404)
    respx.head("http://notfoundcom.s3.amazonaws.com").respond(404)
    respx.head("http://notfound-www.s3.amazonaws.com").respond(404)
    respx.head("http://notfound-backups.s3.amazonaws.com").respond(404)
    respx.head("https://notfound.blob.core.windows.net/").respond(404)
    respx.head("https://notfoundcom.blob.core.windows.net/").respond(404)
    respx.head("https://notfoundassets.blob.core.windows.net/").respond(404)
    respx.head("https://notfoundmedia.blob.core.windows.net/").respond(404)
    respx.head("https://notfound-assets.blob.core.windows.net/").respond(404)
    respx.head("https://notfound-dev.blob.core.windows.net/").respond(404)
    respx.head("https://notfoundprod.blob.core.windows.net/").respond(404)
    respx.head("https://notfound-www.blob.core.windows.net/").respond(404)

    # Allow any other requests to pass through without being mocked or making a real call
    respx.route().pass_through()

    result = await enumerate_cloud_services(domain=domain)

    assert result["s3_buckets"] == []
    assert result["azure_blobs"] == []


@pytest.mark.asyncio
async def test_enumerate_cloud_services_invalid_azure_name():
    """Tests that invalid Azure names (e.g., too short) are skipped."""
    # This test doesn't require mocking because the invalid name `ex`
    # should be filtered out. However, permutations like 'exdev' are valid.
    domain = "ex.com"
    # Mock the valid permutation to avoid network calls
    respx.head("https://exdev.blob.core.windows.net").respond(404)
    respx.head("https://ex.blob.core.windows.net").respond(404)
    respx.head("http://ex.s3.amazonaws.com").respond(404)
    respx.head("http://ex-assets.s3.amazonaws.com").respond(404)
    respx.head("http://ex-dev.s3.amazonaws.com").respond(404)
    respx.head("http://ex-media.s3.amazonaws.com").respond(404)
    respx.head("http://ex-prod.s3.amazonaws.com").respond(404)
    respx.head("http://excom.s3.amazonaws.com").respond(404)
    respx.head("http://ex-www.s3.amazonaws.com").respond(404)
    respx.head("http://ex-backups.s3.amazonaws.com").respond(404)
    respx.head("http://ex.com.s3.amazonaws.com/").respond(404)
    respx.head("https://exbackups.blob.core.windows.net/").respond(404)
    respx.head("https://exprod.blob.core.windows.net/").respond(404)
    respx.head("https://exmedia.blob.core.windows.net/").respond(404)
    respx.head("https://excom.blob.core.windows.net/").respond(404)
    with respx.mock:
        result = await enumerate_cloud_services(domain=domain)
        assert not result["azure_blobs"]
