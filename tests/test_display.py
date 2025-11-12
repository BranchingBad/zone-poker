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
    display_summary,
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
    # Call the function
    result = display_dns_records_table(dns_records_data, quiet=False)

    # Assertions
    assert isinstance(result, Table)
    assert result.row_count == 2
    assert result.caption == "Total: 2 DNS records found"


def test_display_dns_records_table_empty_data():
    """
    Tests that display_dns_records_table handles empty data correctly.
    """
    result = display_dns_records_table({}, quiet=False)

    assert isinstance(result, Table)
    assert result.row_count == 1  # "No records found" row
    assert result.caption == "Total: 0 DNS records found"


def test_display_ptr_lookups_with_data():
    """
    Tests that display_ptr_lookups returns a Table when data is present.
    """
    data = {"1.2.3.4": "rev.example.com"}
    result = display_ptr_lookups(data, quiet=False)

    assert isinstance(result, Table)
    assert result.row_count == 1
    assert result.caption == "Total: 1 PTR lookups performed"


def test_display_ptr_lookups_empty_data():
    """
    Tests that display_ptr_lookups returns a Panel when data is empty.
    """
    result = display_ptr_lookups({}, quiet=False)

    assert isinstance(result, Panel)
    assert "No PTR records to display" in str(result.renderable)


def test_display_axfr_results_vulnerable():
    """
    Tests that display_axfr_results returns a Tree with a 'Vulnerable' summary.
    """
    data = {"summary": "Vulnerable"}
    result = display_axfr_results(data, quiet=False)

    assert isinstance(result, Tree)
    assert "Vulnerable" in str(result.label)


def test_display_whois_info(whois_data):
    """
    Tests that display_whois_info returns a Panel containing a Table.
    """
    result = display_whois_info(whois_data, quiet=False)

    assert isinstance(result, Panel)
    assert result.title == "WHOIS Information"

    # Check the renderable inside the panel, which should be our table
    inner_table = result.renderable
    assert isinstance(inner_table, Table)
    assert inner_table.row_count == 3

    # Check that a key from the data is present
    assert "Registrar" in str(inner_table.columns[0].cells)


def test_display_summary_data_driven():
    """
    Tests the data-driven display_summary function to ensure it correctly
    generates rows and applies styles based on the SUMMARY_CHECKS logic.
    """
    mock_data = {
        "zone_info": {"summary": "Vulnerable (Zone Transfer Successful)"},
        "mail_info": {
            "spf": {"all_policy": "~all"},
            "dmarc": {"p": "reject"},
        },
        "security_info": {"findings": [1, 2]},  # Two findings
    }

    # Call the function
    result = display_summary(mock_data, quiet=False)

    # Assertions
    assert isinstance(result, Table)
    assert result.row_count == 4

    # To inspect the content, we can look at the cells in the columns
    labels = result.columns[0].cells
    findings = result.columns[1].cells

    # 1. Zone Transfer should be 'Vulnerable' and red
    assert labels[0] == "Zone Transfer"
    assert "[bold red]Vulnerable (Zone Transfer Successful)[/bold red]" in str(findings[0])

    # 2. SPF Policy should be '~all' and yellow
    assert labels[1] == "SPF Policy"
    assert "[yellow]~all[/yellow]" in str(findings[1])

    # 3. DMARC Policy should be 'reject' and green
    assert labels[2] == "DMARC Policy"
    assert "[green]reject[/green]" in str(findings[2])

    # 4. Security Audit should show 2 issues and be red
    assert labels[3] == "Security Audit"
    assert "[red]Found 2 issues[/red]" in str(findings[3])
