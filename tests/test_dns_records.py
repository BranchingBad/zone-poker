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


def create_dns_records_mock_side_effect(resolver, outcomes):
    """
    Creates a dynamic side_effect function for mocking asyncio.to_thread calls
    during DNS record lookups.

    Args:
        resolver: The mocked dns.resolver.Resolver object.
        outcomes: A dictionary mapping record types to their mocked outcomes.
                  e.g., {"A": ["1.2.3.4"], "MX": dns.exception.Timeout}
    """

    async def mock_side_effect(*args, **kwargs):
        func, domain, rtype = args
        if func != resolver.resolve:
            raise ValueError(f"Unexpected function call mocked: {func}")

        outcome = outcomes.get(rtype)

        if isinstance(outcome, type) and issubclass(outcome, Exception):
            raise outcome
        elif isinstance(outcome, list):
            # Create mock rdata objects from the provided list of strings
            mock_rdata_list = [MagicMock(to_text=lambda v=val: v) for val in outcome]
            return create_mock_answer(mock_rdata_list)
        else:
            # Default case if rtype is not in outcomes, return an empty answer
            return create_mock_answer([])

    return mock_side_effect


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
    outcomes = {"A": ["1.2.3.4"]}

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = create_dns_records_mock_side_effect(
            mock_resolver, outcomes
        )
        result = await get_dns_records(
            "example.com", mock_resolver, verbose=False, record_types=["A"]
        )

    # Verify the result
    assert "A" in result
    assert len(result["A"]) == 1
    assert result["A"][0]["value"] == "1.2.3.4"


@pytest.mark.asyncio
@patch("modules.analysis.dns_records.console.print")
@patch("modules.analysis.dns_records._format_rdata")
async def test_get_dns_records_no_answer(mock_format, mock_print, mock_resolver):
    """
    Test get_dns_records when a NoAnswer exception is raised.
    """
    # Simulate a NoAnswer exception
    outcomes = {"A": dns.resolver.NoAnswer}
    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = create_dns_records_mock_side_effect(
            mock_resolver, outcomes
        )
        result = await get_dns_records(
            "example.com", mock_resolver, verbose=True, record_types=["A"]
        )

    # Verify the result is an empty list for the given type
    assert "A" in result
    assert result["A"] == []

    # Verify the error message was printed to the console
    mock_print.assert_called_once()
    assert (
        "Error querying A for example.com: The DNS response does not contain an answer to the question."
        in mock_print.call_args[0][0]  # type: ignore
    )


@pytest.mark.asyncio
@patch("modules.analysis.dns_records._format_rdata")
async def test_get_dns_records_timeout(mock_format, mock_resolver):
    """
    Test get_dns_records when a Timeout exception is raised.
    """
    # Simulate a Timeout exception
    outcomes = {"MX": dns.exception.Timeout}
    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = create_dns_records_mock_side_effect(
            mock_resolver, outcomes
        )
        result = await get_dns_records(
            "example.com", mock_resolver, verbose=False, record_types=["MX"]
        )

    assert "MX" in result
    assert result["MX"] == []


@pytest.mark.asyncio
@patch(
    "modules.analysis.dns_records._format_rdata",
    side_effect=lambda rtype, rdata, ttl, name: {"value": rdata.to_text()},
)
async def test_get_dns_records_specific_types(mock_format, mock_resolver):
    """
    Test that only specified record_types are queried.
    """
    # Specify only MX and TXT records
    types_to_query = ["MX", "TXT"]
    outcomes = {"MX": [], "TXT": ["some text"]}

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = create_dns_records_mock_side_effect(
            mock_resolver, outcomes
        )
        result = await get_dns_records(
            "example.com", mock_resolver, verbose=False, record_types=types_to_query
        )

        # Check that resolve was called for each specified type
        assert mock_to_thread.call_count == 2
        mock_to_thread.assert_any_call(mock_resolver.resolve, "example.com", "MX")
        mock_to_thread.assert_any_call(mock_resolver.resolve, "example.com", "TXT")

        # Verify results
        assert result["MX"] == []
        assert result["TXT"][0]["value"] == "some text"
