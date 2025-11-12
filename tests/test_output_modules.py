import pytest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from modules.output import xml as xml_output
from modules.output import html as html_output


@pytest.fixture
def sample_scan_data():
    """Provides a sample data structure similar to `all_data`."""
    return {
        "domain": "example.com",
        "scan_timestamp": "2025-01-01T12:00:00",
        "records": {"A": [{"value": "93.184.216.34", "ttl": 86400,
                           "name": "example.com"}],
                    "MX": [{"value": "mail.example.com", "priority": 10,
                            "ttl": 3600, "name": "example.com"}]},
        "whois": {
            "registrar": "Test Registrar Inc."
        },
        "empty_module": {},  # Test that empty modules are correctly skipped
        "zone_info": None  # Test that None modules are correctly skipped
    }


@patch('modules.output.xml.console.print')
def test_xml_output_generation(mock_console_print, sample_scan_data):
    """
    Tests that the XML output module correctly converts scan data into an XML string.
    """
    # Run the output function
    xml_output.output(sample_scan_data)

    # Check that console.print was called exactly once
    mock_console_print.assert_called_once()

    # Get the XML string that was passed to console.print
    xml_string = mock_console_print.call_args[0][0]

    # Parse the XML string to validate its structure and content
    root = ET.fromstring(xml_string)

    assert root.tag == "scan_results"
    assert root.find("domain").text == "example.com"
    assert root.find("scan_timestamp").text == "2025-01-01T12:00:00"
    assert root.find("records/A/value").text == "93.184.216.34"
    assert root.find("records/MX/priority").text == "10"
    assert root.find("whois/registrar").text == "Test Registrar Inc."
    assert root.find("empty_module") is None  # Ensure empty modules are not added
    assert root.find("zone_info") is None  # Ensure None modules are not added


@patch('builtins.print')
def test_html_output_generation(mock_print, sample_scan_data):
    """
    Tests that the HTML output module correctly generates an HTML string and that it
    contains expected data.
    """
    # Run the HTML output function
    html_output.output(sample_scan_data)

    # Ensure that the final print function was called
    mock_print.assert_called_once()

    # Get the generated HTML string
    html_string = mock_print.call_args[0][0]

    # Perform basic checks on the HTML content
    assert "<html>" in html_string
    assert "DNS Intelligence Report for: example.com" in html_string
    assert "Scan Summary" in html_string  # From display_summary
    assert "WHOIS Information" in html_string  # From a decorated display function
    assert "Test Registrar Inc." in html_string  # The actual data
    assert "DNS Records Discovery" in html_string  # From another decorated function