import pytest
import dns.resolver, dns.rdatatype
import dns.zone
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


@pytest.mark.asyncio
async def test_axfr_successful(mock_resolver, mock_records):
    """Test a successful AXFR."""
    domain = "example.com"

    def do_xfr_success(*args, **kwargs):
        # Simulate a successful zone transfer
        zone_text = f"""
        @ 3600 IN SOA ns1.{domain}. hostmaster.{domain}. 1 2 3 4 5
        {domain}. 3600 IN NS ns1.{domain}.
        """
        return dns.zone.from_text(zone_text, origin=domain)

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = [
            create_mock_answer(["1.1.1.1"]),  # A record for ns1
            create_mock_answer([]),  # AAAA record for ns1
            AsyncMock(return_value=do_xfr_success()),  # AXFR for ns1
            create_mock_answer([]),  # A record for ns2
            create_mock_answer([]),  # AAAA record for ns2
        ]

        results = await attempt_axfr(
            domain, mock_resolver, 5, False, records_info=mock_records
        )

    assert results["summary"] == "Vulnerable (Zone Transfer Successful)"
    assert results["servers"]["ns1.example.com"]["status"] == "Successful"
    assert results["servers"]["ns1.example.com"]["ip_used"] == "1.1.1.1"
    assert results["servers"]["ns1.example.com"]["record_count"] > 0


@pytest.mark.asyncio
async def test_axfr_refused(mock_resolver, mock_records):
    """Test an AXFR that is refused by the server."""
    domain = "example.com"

    def do_xfr_refused(*args, **kwargs):
        # A FormError is raised by dnspython for a refused transfer
        raise dns.exception.FormError("Refused")

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = [
            create_mock_answer(["1.1.1.1"]),
            create_mock_answer([]),
            AsyncMock(side_effect=dns.exception.FormError("Refused")),  # ns1 results
            create_mock_answer(["2.2.2.2"]),
            create_mock_answer([]),
            AsyncMock(side_effect=dns.exception.FormError("Refused")),  # ns2 results
        ]
        results = await attempt_axfr(
            domain, mock_resolver, 5, False, records_info=mock_records
        )

    assert results["summary"] == "Secure (No successful transfers)"
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

    def do_xfr_timeout(*args, **kwargs):
        raise dns.exception.Timeout()

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = [
            create_mock_answer(["1.1.1.1"]),
            create_mock_answer([]),
            AsyncMock(side_effect=dns.exception.Timeout()),  # ns1 results
            create_mock_answer(["2.2.2.2"]),
            create_mock_answer([]),
            AsyncMock(side_effect=dns.exception.Timeout()),  # ns2 results
        ]
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
