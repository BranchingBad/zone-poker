import pytest
import dns.resolver
from unittest.mock import MagicMock, AsyncMock, patch

from modules.analysis.dnsbl import check_dnsbl, DNSBL_PROVIDERS

@pytest.mark.asyncio
async def test_dnsbl_ip_listed():
    """
    Test that an IP is correctly identified as being on a blocklist.
    """
    records = {"A": [{"value": "1.2.3.4"}]}
    resolver = MagicMock()

    # Mock resolver to raise NXDOMAIN for all but one provider
    side_effects = [dns.resolver.NXDOMAIN] * (len(DNSBL_PROVIDERS) - 1) + [MagicMock()] # Last one succeeds
    
    with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = side_effects
        results = await check_dnsbl(records, resolver)

    assert len(results["listed_ips"]) == 1
    assert results["listed_ips"][0]["ip"] == "1.2.3.4"
    assert len(results["listed_ips"][0]["listed_on"]) == 1
    assert results["listed_ips"][0]["listed_on"][0] == DNSBL_PROVIDERS[-1]

@pytest.mark.asyncio
async def test_dnsbl_ip_not_listed():
    """
    Test that a clean IP is not reported.
    """
    records = {"A": [{"value": "4.3.2.1"}]}
    resolver = MagicMock()

    # Mock resolver to always raise NXDOMAIN (not found)
    with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = dns.resolver.NXDOMAIN
        results = await check_dnsbl(records, resolver)

    assert len(results["listed_ips"]) == 0

@pytest.mark.asyncio
async def test_dnsbl_no_ips():
    """
    Test that the function handles cases with no A/AAAA records.
    """
    records = {"MX": [{"value": "mail.example.com"}]}
    resolver = MagicMock()
    results = await check_dnsbl(records, resolver)
    assert len(results["listed_ips"]) == 0