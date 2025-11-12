import pytest
import dns.resolver
import dns.zone
import dns.exception
from unittest.mock import MagicMock, AsyncMock, patch

from modules.analysis.dns_zone import attempt_axfr

@pytest.fixture
def mock_resolver():
    """Fixture for a mock dns.resolver.Resolver."""
    return MagicMock()

@pytest.fixture
def mock_records():
    """Fixture for sample records dictionary with NS records."""
    return {
        "NS": [
            {"value": "ns1.example.com"},
            {"value": "ns2.example.com"}
        ]
    }

@pytest.mark.asyncio
async def test_axfr_successful(mock_resolver, mock_records):
    """Test a successful AXFR."""
    domain = "example.com"
    
    # Mock NS resolution
    async def resolve_side_effect(ns, rtype):
        if ns == "ns1.example.com" and rtype == "A":
            return ["1.1.1.1"]
        return []
    
    with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
        # Mock the resolver inside the helper
        mock_resolver.resolve.side_effect = Exception("Should be mocked by to_thread")
        
        # Mock the top-level to_thread calls
        # First for _resolve_ns_ips, then for _do_xfr
        def do_xfr_success():
            # Simulate a successful zone transfer
            zone_text = f"""
            {domain}. 3600 IN SOA ns1.{domain}. hostmaster.{domain}. 1 2 3 4 5
            {domain}. 3600 IN NS ns1.{domain}.
            """
            zone = dns.zone.from_text(zone_text, origin=domain)
            return zone

        mock_to_thread.side_effect = [
            ["1.1.1.1"], # A record for ns1
            [], # AAAA record for ns1
            do_xfr_success, # Successful AXFR for ns1
            [], # A record for ns2
            [], # AAAA record for ns2
        ]

        results = await attempt_axfr(domain, mock_resolver, 5, False, records_info=mock_records)

    assert results["summary"] == "Vulnerable (Zone Transfer Successful)"
    assert results["servers"]["ns1.example.com"]["status"] == "Successful"
    assert results["servers"]["ns1.example.com"]["ip_used"] == "1.1.1.1"
    assert results["servers"]["ns1.example.com"]["record_count"] > 0

@pytest.mark.asyncio
async def test_axfr_refused(mock_resolver, mock_records):
    """Test an AXFR that is refused by the server."""
    domain = "example.com"

    def do_xfr_refused():
        # A FormError is raised by dnspython for a refused transfer
        raise dns.exception.FormError("Refused")

    with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = [
            ["1.1.1.1"], [], do_xfr_refused, # ns1 results
            ["2.2.2.2"], [], do_xfr_refused, # ns2 results
        ]
        results = await attempt_axfr(domain, mock_resolver, 5, False, records_info=mock_records)

    assert results["summary"] == "Secure (No successful transfers)"
    assert results["servers"]["ns1.example.com"]["status"] == "Failed (Refused or Protocol Error)"
    assert results["servers"]["ns2.example.com"]["status"] == "Failed (Refused or Protocol Error)"

@pytest.mark.asyncio
async def test_axfr_timeout(mock_resolver, mock_records):
    """Test an AXFR that times out."""
    domain = "example.com"

    def do_xfr_timeout():
        raise dns.exception.Timeout()

    with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = [
            ["1.1.1.1"], [], do_xfr_timeout, # ns1 results
            ["2.2.2.2"], [], do_xfr_timeout, # ns2 results
        ]
        results = await attempt_axfr(domain, mock_resolver, 1, False, records_info=mock_records)

    assert results["summary"] == "Secure (No successful transfers)"
    assert results["servers"]["ns1.example.com"]["status"] == "Failed (Timeout)"
    assert results["servers"]["ns2.example.com"]["status"] == "Failed (Timeout)"

@pytest.mark.asyncio
async def test_axfr_ns_not_resolved(mock_resolver, mock_records):
    """Test when a nameserver's IP cannot be resolved."""
    domain = "example.com"
    
    with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
        # All resolution attempts return empty lists
        mock_to_thread.return_value = []
        results = await attempt_axfr(domain, mock_resolver, 5, False, records_info=mock_records)

    assert results["summary"] == "Secure (No successful transfers)"
    assert results["servers"]["ns1.example.com"]["status"] == "Failed (No A/AAAA record for NS)"

@pytest.mark.asyncio
async def test_axfr_no_ns_records(mock_resolver):
    """Test when the domain has no NS records to check."""
    domain = "example.com"
    results = await attempt_axfr(domain, mock_resolver, 5, False, records_info={"NS": []})
    
    assert results["status"] == "Skipped (No NS records found)"
    assert "summary" not in results