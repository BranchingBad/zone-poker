from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone
import pytest

from modules.analysis.dns_zone import attempt_axfr


@pytest.fixture
def mock_resolver():
    """Fixture for a mock dns.resolver.Resolver."""
    resolver = MagicMock(spec=dns.resolver.Resolver)
    resolver.resolve = MagicMock()
    return resolver


def create_mock_answer(records):
    """Helper to create a mock dnspython answer object."""
    mock_records = []
    for r_val in records:
        mock_rec = MagicMock()
        mock_rec.to_text.return_value = r_val
        mock_rec.__str__.return_value = r_val
        mock_records.append(mock_rec)

    answer = MagicMock()
    answer.__iter__.return_value = iter(mock_records)
    return answer


@pytest.fixture
def mock_records():
    """Fixture for sample records dictionary with NS records."""
    return {"NS": [{"value": "ns1.example.com"}, {"value": "ns2.example.com"}]}


def create_axfr_mock_side_effect(resolver, xfr_outcomes, domain="example.com"):
    """
    Creates a dynamic side_effect function for mocking asyncio.to_thread calls
    during an AXFR attempt.
    """

    def do_xfr_success(*args, **kwargs):
        zone_text = f"$ORIGIN {domain}.\n@ 3600 IN SOA ns1.{domain}. hostmaster.{domain}. 1 2 3 4 5\n@ 3600 IN NS ns1.{domain}."
        return dns.zone.from_text(zone_text, origin=domain)

    # We need to track which IP maps to which outcome
    ns_ip_to_outcome = {}
    for ns, outcome in xfr_outcomes.items():
        for ip in outcome.get("a", []):
            ns_ip_to_outcome[ip] = outcome.get("xfr")
        for ip in outcome.get("aaaa", []):
            ns_ip_to_outcome[ip] = outcome.get("xfr")

    async def mock_side_effect(*args, **kwargs):
        func = args[0]
        func_args = args[1:]

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
            ns_ip = func_args[0]
            outcome = ns_ip_to_outcome.get(ns_ip)

            if outcome == "success":
                # The real function returns an iterator, so we mock that.
                # The content of the iterator is processed by dns.zone.from_xfr,
                # which we don't need to deeply mock. Just returning a success
                # marker is enough if we adjust the code to not use from_xfr.
                # For now, let's assume the success case is handled by a simple return
                # and the calling test will validate the 'status' field.
                # A more robust mock would return a generator of dns.rrset objects.
                # Let's return a mock that can be iterated.
                return iter([])
            elif outcome == "refused":
                raise dns.query.TransferError("Transfer refused")
            elif outcome == "timeout":
                raise dns.exception.Timeout()
            elif outcome == "protocol_error":
                raise dns.query.FormError("Protocol error")

        # If we fall through, it's an unhandled call
        raise ValueError(
            f"Unhandled mock call for {getattr(func, '__name__', 'unknown_func')} with args {func_args}"
        )

    return mock_side_effect


@pytest.mark.asyncio
async def test_axfr_ns_not_resolved(mock_resolver, mock_records):
    """Test when a nameserver's IP cannot be resolved."""
    # Define outcomes where NS servers have no A/AAAA records
    xfr_outcomes = {
        "ns1.example.com": {"a": [], "aaaa": [], "xfr": "refused"},
        "ns2.example.com": {"a": [], "aaaa": [], "xfr": "refused"},
    }

    with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        mock_to_thread.side_effect = create_axfr_mock_side_effect(
            mock_resolver, xfr_outcomes, "example.com"
        )
        results = await attempt_axfr(
            "example.com", mock_resolver, 5, False, records_info=mock_records
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
