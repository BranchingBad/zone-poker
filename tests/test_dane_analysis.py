import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import dns.resolver
import dns.exception

from modules.analysis.dane_analysis import analyze_dane_records


@pytest.fixture
def mock_resolver():
    """Fixture to create a mock dns.resolver.Resolver."""
    resolver = MagicMock(spec=dns.resolver.Resolver)  # We use AsyncMock for `resolve`
    # because it's called via asyncio.to_thread
    resolver.resolve = AsyncMock()
    return resolver


def create_mock_answer(records):
    """Helper to create a mock dnspython answer object."""
    answer = MagicMock()
    answer.__iter__.return_value = iter(records)
    return answer


@pytest.mark.asyncio
async def test_analyze_dane_records_found(mock_resolver):
    """
    Test analyze_dane_records when TLSA records are found.
    """
    domain = "example.com"
    target = f"_443._tcp.{domain}"
    mock_answer = create_mock_answer(["3 1 1 ..."])

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.return_value = mock_answer
        results = await analyze_dane_records(domain, mock_resolver)

    mock_to_thread.assert_awaited_with(mock_resolver.resolve, target, "TLSA")
    assert results["status"] == "Present"
    assert len(results["records"]) == 1
    assert results["records"][0] == "3 1 1 ..."


@pytest.mark.asyncio
async def test_analyze_dane_records_not_found(mock_resolver):
    """
    Test analyze_dane_records when no TLSA records are found (NoAnswer).
    """
    domain = "example.com"
    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = dns.resolver.NoAnswer
        results = await analyze_dane_records(domain, mock_resolver)

    assert results["status"] == "Not Found"
    assert len(results["records"]) == 0


@pytest.mark.asyncio
async def test_analyze_dane_records_error(mock_resolver):
    """
    Test analyze_dane_records when a DNS query error occurs.
    """
    domain = "example.com"
    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = dns.exception.Timeout
        results = await analyze_dane_records(domain, mock_resolver)

    assert results["status"] == "Error: Timeout"
