import pytest
import dns.resolver
import dns.exception
from unittest.mock import MagicMock, AsyncMock, patch

from modules.analysis.dns_records import get_dns_records


@pytest.fixture
def mock_resolver():
    """Fixture to create a mock dns.resolver.Resolver."""
    resolver = MagicMock(spec=dns.resolver.Resolver)  # type: ignore
    # We use AsyncMock for `resolve` because it's called via asyncio.to_thread
    resolver.resolve = AsyncMock()
    return resolver


def create_mock_answer(records, ttl=300, name="example.com"):
    """Helper to create a mock dnspython answer object."""
    answer = MagicMock()
    answer.name = name
    answer.ttl = ttl
    answer.__iter__.return_value = iter(records)
    return answer


@pytest.mark.asyncio
@patch('modules.analysis.dns_records._format_rdata',
       side_effect=lambda rtype, rdata, ttl, name: {"value": rdata}
       )
async def test_get_dns_records_success(mock_format, mock_resolver):
    """
    Test get_dns_records for a successful query.
    """
    # Simulate a successful response for an 'A' record
    mock_answer = create_mock_answer([MagicMock(to_text=lambda: "1.2.3.4")])
    mock_resolver.resolve.return_value = mock_answer

    result = await get_dns_records(
        "example.com", mock_resolver, verbose=False, record_types=["A"])

    # Verify resolve was called correctly
    mock_resolver.resolve.assert_called_once_with("example.com", "A")
    # Verify the result
    assert "A" in result
    assert len(result["A"]) == 1
    assert result["A"][0]["value"].to_text() == "1.2.3.4"


@pytest.mark.asyncio
@patch('modules.analysis.dns_records._format_rdata')
async def test_get_dns_records_no_answer(mock_format, mock_resolver, capsys):
    """
    Test get_dns_records when a NoAnswer exception is raised.
    """
    # Simulate a NoAnswer exception
    mock_resolver.resolve.side_effect = dns.resolver.NoAnswer("No A records found.")

    result = await get_dns_records(
        "example.com", mock_resolver, verbose=True, record_types=["A"])

    # Verify the result is an empty list for the given type
    assert "A" in result
    assert result["A"] == []

    # Verify the error message was printed to the console
    captured = capsys.readouterr()
    assert "Error querying A for example.com: No A records found." in captured.out


@pytest.mark.asyncio
@patch('modules.analysis.dns_records._format_rdata')
async def test_get_dns_records_timeout(mock_format, mock_resolver):
    """
    Test get_dns_records when a Timeout exception is raised.
    """
    # Simulate a Timeout exception
    mock_resolver.resolve.side_effect = dns.exception.Timeout("Query timed out.")

    result = await get_dns_records(
        "example.com", mock_resolver, verbose=False, record_types=["MX"])

    assert "MX" in result
    assert result["MX"] == []


@pytest.mark.asyncio
@patch('modules.analysis.dns_records._format_rdata')
async def test_get_dns_records_specific_types(mock_format, mock_resolver):
    """
    Test that only specified record_types are queried.
    """
    mock_resolver.resolve.return_value = create_mock_answer([])

    # Specify only MX and TXT records
    types_to_query = ["MX", "TXT"]

    await get_dns_records(
        "example.com", mock_resolver, verbose=False, record_types=types_to_query)

    # Check that resolve was called for each specified type
    assert mock_resolver.resolve.call_count == 2
    mock_resolver.resolve.assert_any_call("example.com", "MX")
    mock_resolver.resolve.assert_any_call("example.com", "TXT")