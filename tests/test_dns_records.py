import pytest
import dns.resolver
import dns.exception
from unittest.mock import MagicMock, AsyncMock, patch

from modules.analysis.dns_records import get_dns_records


@pytest.fixture
def mock_resolver():
    """Fixture to create a mock dns.resolver.Resolver."""
    resolver = MagicMock(spec=dns.resolver.Resolver)  # resolve is synchronous
    resolver.resolve = MagicMock()
    return resolver


def create_mock_answer(records, ttl=300, name="example.com"):
    """Helper to create a mock dnspython answer object."""
    answer = MagicMock()
    answer.name = name
    answer.ttl = ttl
    answer.__iter__.return_value = iter(records)
    return answer


@pytest.mark.asyncio
@patch(
    "modules.analysis.dns_records._format_rdata",
    side_effect=lambda rtype, rdata, ttl, name: {"value": rdata.to_text()},
)
async def test_get_dns_records_success(mock_format, mock_resolver):
    """
    Test get_dns_records for a successful query.
    """
    # Simulate a successful response for an 'A' record
    mock_answer = create_mock_answer([MagicMock(to_text=lambda: "1.2.3.4")])

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.return_value = mock_answer
        result = await get_dns_records(
            "example.com", mock_resolver, verbose=False, record_types=["A"]
        )

    # Verify resolve was called correctly
    mock_to_thread.assert_called_once_with(mock_resolver.resolve, "example.com", "A")

    # Verify the result
    assert "A" in result
    assert len(result["A"]) == 1
    assert result["A"][0]["value"] == "1.2.3.4"


@pytest.mark.asyncio
@patch("modules.analysis.dns_records._format_rdata")
async def test_get_dns_records_no_answer(mock_format, mock_resolver, capsys):
    """
    Test get_dns_records when a NoAnswer exception is raised.
    """
    # Simulate a NoAnswer exception
    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = dns.resolver.NoAnswer
        result = await get_dns_records(
            "example.com", mock_resolver, verbose=True, record_types=["A"]
        )

    # Verify the result is an empty list for the given type
    assert "A" in result
    assert result["A"] == []

    # Verify the error message was printed to the console
    captured = capsys.readouterr()
    assert "Error querying A for example.com: No A records found." in captured.err


@pytest.mark.asyncio
@patch("modules.analysis.dns_records._format_rdata")
async def test_get_dns_records_timeout(mock_format, mock_resolver):
    """
    Test get_dns_records when a Timeout exception is raised.
    """
    # Simulate a Timeout exception
    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = dns.exception.Timeout
        result = await get_dns_records(
            "example.com", mock_resolver, verbose=False, record_types=["MX"]
        )

    assert "MX" in result
    assert result["MX"] == []


@pytest.mark.asyncio
@patch("modules.analysis.dns_records._format_rdata")
async def test_get_dns_records_specific_types(mock_format, mock_resolver):
    """
    Test that only specified record_types are queried.
    """
    # Specify only MX and TXT records
    types_to_query = ["MX", "TXT"]

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.return_value = create_mock_answer([])
        await get_dns_records(
            "example.com", mock_resolver, verbose=False, record_types=types_to_query
        )

        # Check that resolve was called for each specified type
        assert mock_to_thread.call_count == 2
        mock_to_thread.assert_any_call(mock_resolver.resolve, "example.com", "MX")
        mock_to_thread.assert_any_call(mock_resolver.resolve, "example.com", "TXT")
