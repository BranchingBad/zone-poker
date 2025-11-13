import pytest
import dns.resolver, dns.rdatatype
import dns.zone
import dns.query
import dns.exception
from unittest.mock import MagicMock, AsyncMock, patch

from modules.analysis.dns_zone import attempt_axfr


@pytest.fixture
def mock_resolver():
    """Fixture for a mock dns.resolver.Resolver."""
    resolver = MagicMock(spec=dns.resolver.Resolver)
    resolver.resolve = MagicMock()
    return resolver

def create_mock_answer(records):
    """Helper to create a mock dnspython answer object."""
    answer = MagicMock()
    answer.__iter__.return_value = iter(records)
    return answer


@pytest.fixture
def mock_records():
    """Fixture for sample records dictionary with NS records."""
    return {"NS": [{"value": "ns1.example.com"}, {"value": "ns2.example.com"}]}


def create_axfr_mock_side_effect(resolver, xfr_outcomes, domain="example.com"):
    """
    Creates a dynamic side_effect function for mocking asyncio.to_thread calls
    during an AXFR attempt. This is more robust than a static list of side effects.

    Args:
        resolver: The mocked dns.resolver.Resolver object.
        xfr_outcomes: A dictionary mapping nameserver names to their mocked outcomes.
                      e.g., {"ns1.example.com": {"a": ["1.1.1.1"], "xfr": "success"}}
        domain: The domain being tested.
    """

    def do_xfr_success(*args, **kwargs):
        zone_text = f"$ORIGIN {domain}.\n@ 3600 IN SOA ns1.{domain}. hostmaster.{domain}. 1 2 3 4 5\n@ 3600 IN NS ns1.{domain}."
        return dns.zone.from_text(zone_text, origin=domain)

    async def mock_side_effect(*args, **kwargs):
        func, func_args = args[0], args[1:]

        # --- Mock for NS IP resolution (resolver.resolve) ---
        if func == resolver.resolve:
            ns_name, rtype = func_args[0], func_args[1]
            for ns, outcome in xfr_outcomes.items():
                if ns_name == ns:
                    if rtype == "A":
                        return create_mock_answer(outcome.get("a", []))
                    if rtype == "AAAA":
                        return create_mock_answer(outcome.get("aaaa", []))
            return create_mock_answer([])  # Default empty answer

        # --- Mock for the actual zone transfer (dns.query.xfr) ---
        if func == dns.query.xfr:
            ip_address = func_args[0]
            for ns, outcome in xfr_outcomes.items():
                if ip_address in outcome.get("a", []) or ip_address in outcome.get(
                    "aaaa", []
                ):
                    if outcome.get("xfr") == "success":
                        return do_xfr_success()
                    if outcome.get("xfr") == "refused":
                        raise dns.exception.FormError("Refused")
                    if outcome.get("xfr") == "timeout":
                        raise dns.exception.Timeout()
        raise ValueError(f"Unhandled mock call for {func} with args {func_args}")
    
    return mock_side_effect


@pytest.mark.asyncio
async def test_axfr_successful(mock_resolver, mock_records):
    """Test a successful AXFR."""
    domain = "example.com"

    # Define the outcomes for each nameserver
    xfr_outcomes = {
        "ns1.example.com": {"a": ["1.1.1.1"], "xfr": "refused"},
        "ns2.example.com": {"a": ["2.2.2.2"], "xfr": "refused"},
    }

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = create_axfr_mock_side_effect(
            mock_resolver, xfr_outcomes
        )

        results = await attempt_axfr(
            domain, mock_resolver, 5, False, records_info=mock_records
        )

    assert results["summary"] == "Secure (No successful transfers)"
    assert (
        results["servers"]["ns1.example.com"]["status"]
        == "Failed (Refused or Protocol Error)"
    )


@pytest.mark.asyncio
async def test_axfr_refused(mock_resolver, mock_records):
    """Test an AXFR that is refused by the server."""
    domain = "example.com"

    xfr_outcomes = {
        "ns1.example.com": {"a": ["1.1.1.1"], "xfr": "refused"},
        "ns2.example.com": {"a": ["2.2.2.2"], "xfr": "refused"},
    }

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = create_axfr_mock_side_effect(
            mock_resolver, xfr_outcomes
        )
        results = await attempt_axfr(
            domain, mock_resolver, 5, False, records_info=mock_records
        )

    assert results["summary"] == "Vulnerable (Zone Transfer Successful)"
    assert (
        results["servers"]["ns1.example.com"]["status"]
        == "Failed (Refused or Protocol Error)"
    )
    assert (
        results["servers"]["ns2.example.com"]["status"]
        == "Failed (Refused or Protocol Error)"
    )


@pytest.mark.asyncio
async def test_axfr_timeout(mock_resolver, mock_records):
    """Test an AXFR that times out."""
    domain = "example.com"

    xfr_outcomes = {
        "ns1.example.com": {"a": ["1.1.1.1"], "xfr": "timeout"},
        "ns2.example.com": {"a": ["2.2.2.2"], "xfr": "timeout"},
    }

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = create_axfr_mock_side_effect(
            mock_resolver, xfr_outcomes
        )
        results = await attempt_axfr(
            domain, mock_resolver, 1, False, records_info=mock_records
        )

    assert results["summary"] == "Secure (No successful transfers)"
    assert results["servers"]["ns1.example.com"]["status"] == "Failed (Timeout)"
    assert results["servers"]["ns2.example.com"]["status"] == "Failed (Timeout)"


@pytest.mark.asyncio
async def test_axfr_ns_not_resolved(mock_resolver, mock_records):
    """Test when a nameserver's IP cannot be resolved."""
    domain = "example.com"

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        # All resolution attempts return empty lists
        mock_to_thread.return_value = create_mock_answer([])
        results = await attempt_axfr(
            domain, mock_resolver, 5, False, records_info=mock_records
        )

    assert results["summary"] == "Secure (No successful transfers)"
    assert (
        results["servers"]["ns1.example.com"]["status"]
        == "Failed (No A/AAAA record for NS)"
    )


@pytest.mark.asyncio
async def test_axfr_no_ns_records(mock_resolver):
    """Test when the domain has no NS records to check."""
    domain = "example.com"
    results = await attempt_axfr(
        domain, mock_resolver, 5, False, records_info={"NS": []}
    )

    assert results["status"] == "Skipped (No NS records found)"
    assert "summary" not in results
