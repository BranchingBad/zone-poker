import pytest
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

# Import the functions to be tested
from modules.display import (
    display_dns_records_table,
    display_ptr_lookups,
    display_axfr_results,
    display_whois_info,
)


@pytest.fixture
def dns_records_data():
    """Provides sample DNS records data."""
    return {
        "A": [{"value": "1.2.3.4", "ttl": 3600}],
        "MX": [{"value": "mail.example.com", "ttl": 1800, "priority": 10}],
    }


@pytest.fixture
def whois_data():
    """Provides sample WHOIS data."""
    return {
        "domain_name": "example.com",
        "registrar": "Test Registrar",
        "creation_date": "2020-01-01T00:00:00",
    }


def test_display_dns_records_table_with_data(dns_records_data):
    """
    Tests that display_dns_records_table returns a Table with the correct caption
    when data is present.
    """
    # Access the original function wrapped by the decorator
    undecorated_func = display_dns_records_table.__wrapped__

    # Call the original function
    result = undecorated_func(dns_records_data, quiet=False)

    # Assertions
    assert isinstance(result, Table)
    assert result.row_count == 2
    assert result.caption == "Total: 2 DNS records found"


def test_display_dns_records_table_empty_data():
    """
    Tests that display_dns_records_table handles empty data correctly.
    """
    undecorated_func = display_dns_records_table.__wrapped__
    result = undecorated_func({}, quiet=False)

    assert isinstance(result, Table)
    assert result.row_count == 1  # "No records found" row
    assert result.caption == "Total: 0 DNS records found"


def test_display_ptr_lookups_with_data():
    """
    Tests that display_ptr_lookups returns a Table when data is present.
    """
    undecorated_func = display_ptr_lookups.__wrapped__
    data = {"1.2.3.4": "rev.example.com"}
    result = undecorated_func(data, quiet=False)

    assert isinstance(result, Table)
    assert result.row_count == 1
    assert result.caption == "Total: 1 PTR lookups performed"


def test_display_ptr_lookups_empty_data():
    """
    Tests that display_ptr_lookups returns a Panel when data is empty.
    """
    undecorated_func = display_ptr_lookups.__wrapped__
    result = undecorated_func({}, quiet=False)

    assert isinstance(result, Panel)
    assert "No PTR records to display" in str(result.renderable)


def test_display_axfr_results_vulnerable():
    """
    Tests that display_axfr_results returns a Tree with a 'Vulnerable' summary.
    """
    undecorated_func = display_axfr_results.__wrapped__
    data = {"summary": "Vulnerable"}
    result = undecorated_func(data, quiet=False)

    assert isinstance(result, Tree)
    assert "Vulnerable" in str(result.label)


def test_display_whois_info(whois_data):
    """
    Tests that display_whois_info returns a Panel containing a Table.
    """
    undecorated_func = display_whois_info.__wrapped__
    result = undecorated_func(whois_data, quiet=False)

    assert isinstance(result, Panel)
    assert result.title == "WHOIS Information"

    # Check the renderable inside the panel, which should be our table
    inner_table = result.renderable
    assert isinstance(inner_table, Table)
    assert inner_table.row_count == 3

    # Check that a key from the data is present
    assert "Registrar" in str(inner_table.columns[0].cells)