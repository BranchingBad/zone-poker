import pytest
import json
import xml.etree.ElementTree as ET
from unittest.mock import patch

from modules.output import xml as xml_output
from modules.output import html as html_output
from modules.output import json as json_output
from modules.output import csv as csv_output


@pytest.fixture
def sample_scan_data():
    """Provides a sample data structure similar to `all_data`."""
    return {
        "domain": "example.com",
        "scan_timestamp": "2025-01-01T12:00:00",
        # These keys match `data_key` in the dispatch table
        "records_info": {"A": [{"value": "93.184.216.34"}]},
        "whois_info": {"registrar": "Test Registrar Inc."},
        "mail_info": {"spf": {"raw": "v=spf1 -all", "all_policy": "-all"}},
        "zone_info": {},  # Test that empty modules are correctly skipped
        "ptr_info": None,  # Test that None modules are correctly skipped
        "internal_data": {"should_not_be_included": True},
    }


@patch("builtins.print")
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
    assert root.find("records_info/A/value").text == "93.184.216.34"
    assert root.find("whois_info/registrar").text == "Test Registrar Inc."
    # Check that empty, None, or non-module data is excluded
    assert root.find("zone_info") is None
    assert root.find("ptr_info") is None
    assert root.find("internal_data") is None


@patch("builtins.print")
def test_json_output_filtering(mock_print, sample_scan_data):
    """
    Tests that the JSON output correctly filters data, only including modules
    that were run and produced non-empty results.
    """
    # Run the JSON output function
    json_output.output(sample_scan_data)

    # Get the generated JSON string
    json_string = mock_print.call_args[0][0]
    parsed_json = json.loads(json_string)

    # Check for expected data
    assert "domain" in parsed_json
    assert "records_info" in parsed_json
    assert "whois_info" in parsed_json
    # Check that empty, None, or non-module data is correctly excluded
    assert "zone_info" not in parsed_json
    assert "ptr_info" not in parsed_json
    assert "internal_data" not in parsed_json


@patch("builtins.print")
def test_csv_output_generation(mock_print, sample_scan_data):
    """
    Tests that the CSV output correctly generates a multi-section report.
    """
    # Run the CSV output function
    csv_output.output(sample_scan_data)

    # Get the generated CSV string
    csv_string = mock_print.call_args[0][0]

    # Basic checks to ensure different sections are present
    assert "DNS Records" in csv_string
    assert "93.184.216.34" in csv_string

    assert "WHOIS Information" in csv_string
    assert "Test Registrar Inc." in csv_string

    assert "Email Security Information" in csv_string
    assert "v=spf1 -all" in csv_string

    # Check that sections with no data are handled gracefully
    assert "HTTP Security Headers Analysis" in csv_string
    assert "No HTTP security header information found." in csv_string

    assert "SSL/TLS Certificate Analysis" in csv_string
    assert "No SSL/TLS certificate information found." in csv_string


@patch("builtins.print")
def test_html_output_generation(mock_print, sample_scan_data):
    """
    Tests that the HTML output module correctly generates an HTML string and that it
    contains expected data.
    """
    # Run the HTML output function
    html_output.output(sample_scan_data)

    # Ensure that the final print function was called
    assert mock_print.called

    # Get the generated HTML string
    html_string = mock_print.call_args[0][0]

    # Perform basic checks on the HTML content
    assert "<html>" in html_string
    assert "DNS Intelligence Report for: example.com" in html_string
    assert "Scan Summary" in html_string  # From display_summary
    assert "WHOIS Information" in html_string
    assert "Test Registrar Inc." in html_string  # The actual data
    assert "DNS Records Discovery" in html_string
