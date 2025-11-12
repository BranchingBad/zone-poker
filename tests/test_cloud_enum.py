import pytest
import respx
import logging
from httpx import RequestError

from modules.analysis.cloud_enum import enumerate_cloud_services


@pytest.fixture
def mock_routes():
    """A pytest fixture to mock all potential routes.

    This prevents any real network requests from being made.
    """
    domain = "example.com"
    base_name = "example"

    # S3 permutations from the function
    s3_permutations = {
        base_name, f"{base_name}-assets", f"{base_name}-prod", f"{base_name}-dev",
        f"{base_name}-backups", f"{base_name}-media", f"{base_name}-www", domain,
    }

    # Azure permutations from the function
    azure_permutations = {
        "example", "exampleassets", "exampleprod", "exampledev",
        "examplebackups", "examplemedia", "examplewww", "examplecom",
    }

    with respx.mock as mock:
        # Default all routes to 404 Not Found
        for p in s3_permutations:
            mock.head(f"http://{p}.s3.amazonaws.com").respond(404)
        for p in azure_permutations:
            if 3 <= len(p) <= 24 and p.isalnum():
                mock.head(f"https://{p}.blob.core.windows.net").respond(404)

        yield mock


@pytest.mark.asyncio
async def test_enumerate_cloud_services_found(mock_routes):
    """
    Test enumerate_cloud_services when S3 and Azure services are found.
    """
    domain = "example.com"

    # Override the default 404 for specific "found" routes
    mock_routes.head("http://example-prod.s3.amazonaws.com").respond(200)  # Public
    mock_routes.head("http://example-assets.s3.amazonaws.com").respond(403)  # Forbidden
    mock_routes.head("https://example.blob.core.windows.net").respond(400)  # Found

    results = await enumerate_cloud_services(domain)

    # Assert S3 results (should be sorted by URL)
    assert len(results["s3_buckets"]) == 2
    assert results["s3_buckets"][0] == {
        "url": "http://example-assets.s3.amazonaws.com", "status": "forbidden"
    }
    assert results["s3_buckets"][1] == {
        "url": "http://example-prod.s3.amazonaws.com", "status": "public"
    }

    # Assert Azure results
    assert len(results["azure_blobs"]) == 1
    assert results["azure_blobs"][0] == {
        "url": "https://example.blob.core.windows.net", "status": "forbidden"
    }


@pytest.mark.asyncio
async def test_enumerate_cloud_services_not_found(mock_routes):
    """
    Test enumerate_cloud_services when no services are found (all return 404).
    """
    domain = "example.com"

    # All routes are already mocked to 404 by the fixture
    results = await enumerate_cloud_services(domain)

    assert len(results["s3_buckets"]) == 0
    assert len(results["azure_blobs"]) == 0


@pytest.mark.asyncio
async def test_enumerate_cloud_services_network_error(mock_routes, caplog):
    """
    Test that a network error during one check doesn't stop the others.
    """
    caplog.set_level(logging.INFO)
    domain = "example.com"

    # Mock one route to raise an error
    mock_routes.head("http://example-dev.s3.amazonaws.com").mock(
        side_effect=RequestError("Connection failed")
    )

    # Mock another route as found to ensure the function continues
    mock_routes.head("http://example-prod.s3.amazonaws.com").respond(200)

    results = await enumerate_cloud_services(domain)

    # Check that the error was logged
    assert "S3 check for 'example-dev' failed: Connection failed" in caplog.text

    # Check that the other bucket was still found
    assert len(results["s3_buckets"]) == 1
    assert results["s3_buckets"][0] == {
        "url": "http://example-prod.s3.amazonaws.com", "status": "public"
    }