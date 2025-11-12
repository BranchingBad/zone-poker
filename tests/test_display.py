import pytest
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

# Import the functions to be tested
from modules.display import (
    display_dns_records_table,
    display_ptr_lookups,
    display_security_audit,
    display_subdomain_takeover,
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
def security_audit_data_weak():
    """Provides sample security audit data with findings."""
    return {
        "findings": [
            {
                "finding": "Subdomain Takeover",
                "severity": "Critical",
                "recommendation": "Remove dangling DNS records.",
            },
            {
                "finding": "Missing DMARC Record",
                "severity": "High",
                "recommendation": "Implement a DMARC record.",
            },
        ]
    }


@pytest.fixture
def security_audit_data_secure():
    """Provides sample security audit data with no findings."""
    return {"findings": []}


def test_display_dns_records_table_with_data(dns_records_data):
    """
    Tests that display_dns_records_table returns a Table with the correct caption
    when data is present.
    """
    result = display_dns_records_table(dns_records_data, quiet=False)

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


def test_display_security_audit_with_findings(security_audit_data_weak):
    """
    Tests that display_security_audit returns a Panel containing a Tree when
    findings are present.
    """
    result = display_security_audit(security_audit_data_weak, quiet=False)

    assert isinstance(result, Panel)
    assert isinstance(result.renderable, Tree)
    assert "Critical Severity Findings" in str(result.renderable)
    assert "High Severity Findings" in str(result.renderable)


def test_display_security_audit_no_findings(security_audit_data_secure):
    """
    Tests that display_security_audit returns a simple success Panel when no
    findings are present.
    """
    result = display_security_audit(security_audit_data_secure, quiet=False)

    assert isinstance(result, Panel)
    assert "All security checks passed" in str(result.renderable)


def test_display_subdomain_takeover_vulnerable():
    """
    Tests the display for a vulnerable subdomain takeover scenario.
    """
    data = {
        "vulnerable": [
            {
                "subdomain": "test.example.com",
                "service": "S3",
                "cname_target": "test.s3.amazonaws.com",
            }
        ]
    }
    result = display_subdomain_takeover(data, quiet=False)
    assert isinstance(result, Panel)
    assert "Found 1 potential subdomain takeovers" in str(result.renderable.label)


def test_display_summary_data_driven():
    """
    Tests the data-driven display_summary function to ensure it correctly
    generates rows and applies styles based on the SUMMARY_CHECKS logic.
    """
    mock_data = {
        "zone_info": {"summary": "Vulnerable (Zone Transfer Successful)"},
        "mail_info": {"spf": {"all_policy": "~all"}, "dmarc": {"p": "reject"}},
        "security_info": {"findings": [1, 2]},  # Two findings
    }

    result = display_summary(mock_data, quiet=False)

    assert isinstance(result, Table)
    assert result.row_count == 4

    labels = result.columns[0].cells
    findings = result.columns[1].cells

    assert labels[0] == "Zone Transfer"
    assert "[bold red]Vulnerable (Zone Transfer Successful)[/bold red]" in str(
        findings[0]
    )
    assert labels[3] == "Security Audit"
    assert "[red]Found 2 issues[/red]" in str(findings[3])
