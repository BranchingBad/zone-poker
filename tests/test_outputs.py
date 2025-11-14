import json
import argparse
import pytest
import yaml
import xml.etree.ElementTree as ET
from unittest.mock import patch, mock_open

from modules.output import json as json_output, yaml as yaml_output, xml as xml_output
from modules.output import csv as csv_output, html as html_output, txt as txt_output
from tests.conftest import MOCK_DISPATCH_TABLE


# The HTML and CSV modules have their own internal data filtering,
# so we don't need to mock the dispatch table for them.


@pytest.fixture
def sample_scan_data():
    """Provides a sample data structure that mimics `all_data`."""
    # The CSV and HTML modules use a different structure than the others.
    # They rely on the args_namespace and a different key for DNS records.
    args = argparse.Namespace(records=True, whois=True, mail=True, zone=False, security=True)
    return {
        "domain": "example.com",
        "scan_timestamp": "2025-11-14T21:15:18Z",
        "args_namespace": args,
        "records_info": {"A": [{"value": "1.2.3.4"}]},  # Key for DNS records
        "whois_info": {"registrar": "Test Registrar"},
        "mail_info": {"spf": {"raw": "v=spf1 -all"}},
        "security_info": {},  # For summary export
        "zone_info": {},  # Empty module to test filtering
    }


@pytest.fixture
def simple_scan_data():
    """Provides a simple data structure for JSON/XML/YAML tests."""
    return {
        "domain": "example.com",
        "scan_timestamp": "2025-11-14T21:15:18Z",
        "dns_info": {"A": ["1.2.3.4"]},
        "whois_info": {},  # This key has empty data and should be excluded.
        "some_other_internal_data": "this should not be in the report",
    }


@patch("modules.output._base.MODULE_DISPATCH_TABLE", MOCK_DISPATCH_TABLE)
class TestYamlOutput:
    """Unit tests for the YAML output module."""

    def test_yaml_output_to_console(self, capsys, simple_scan_data):
        """
        Verifies that YAML output is correctly printed to standard output.
        """
        # Run the output function without an output_path
        yaml_output.output(simple_scan_data)
        captured = capsys.readouterr()

        # Parse the captured stdout content as YAML
        output_data = yaml.safe_load(captured.out)

        # Assert that the core data and the module with results are present
        assert output_data["domain"] == "example.com"
        assert "dns_info" in output_data
        assert output_data["dns_info"]["A"] == ["1.2.3.4"]

        # Assert that keys with no data or not in the dispatch table are excluded
        assert "whois_info" not in output_data
        assert "some_other_internal_data" not in output_data

    def test_yaml_output_to_file(self, simple_scan_data):
        """
        Verifies that YAML output is correctly written to a file.
        """
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            yaml_output.output(simple_scan_data, output_path="/fake/report.yaml")

        # Ensure the file was opened correctly
        mock_file.assert_called_once_with("/fake/report.yaml", "w", encoding="utf-8")

        # Verify the content written to the file
        written_content = "".join(call.args[0] for call in mock_file().write.call_args_list)
        output_data = yaml.safe_load(written_content)

        assert output_data["domain"] == "example.com"
        assert "dns_info" in output_data
        assert "whois_info" not in output_data

    def test_yaml_output_does_not_contain_tuple_tags(self, capsys, simple_scan_data):
        """
        Verifies that the custom YAML dumper correctly serializes tuples as
        standard lists, without the '!!python/tuple' tag.
        """
        # Add data that contains a tuple
        simple_scan_data["ssl_info"] = {"cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)}

        yaml_output.output(simple_scan_data)
        yaml_string = capsys.readouterr().out

        assert "!!python/tuple" not in yaml_string
        assert "- TLS_AES_256_GCM_SHA384" in yaml_string

    def test_yaml_output_excludes_modules_with_errors(self, capsys, simple_scan_data):
        """
        Verifies that modules containing a top-level 'error' key are excluded
        from the YAML output.
        """
        # Add a module's data that contains an error
        simple_scan_data["reputation_info"] = {
            "error": "API key not found",
            "some_data": "this should not be included",
        }

        yaml_output.output(simple_scan_data)
        yaml_string = capsys.readouterr().out
        output_data = yaml.safe_load(yaml_string)

        assert "reputation_info" not in output_data


class TestTxtOutput:
    """Unit tests for the TXT output module."""

    def test_txt_output_to_console(self, capsys, sample_scan_data):
        """
        Verifies that TXT output is correctly printed to standard output and
        that it only includes sections for modules that were run.
        """
        # Define a simple dispatch table for this test case.
        # This avoids complex patching and makes the test's intent clear.
        test_dispatch_table = {
            "records": {"data_key": "records_info", "export_func": lambda data: "== DNS Records =="},
            "whois": {"data_key": "whois_info"},  # No export_func, should be skipped
        }

        # We can directly mock the other two functions that are called.
        with (
            patch("modules.output.txt.export_txt_summary", return_value="== Scan Summary =="),
            patch("modules.output.txt.export_txt_critical_findings", return_value="== Critical Findings =="),
        ):
            txt_output.output(sample_scan_data, dispatch_table=test_dispatch_table)

        captured = capsys.readouterr()
        report = captured.out

        assert "Zone-Poker Report for: example.com" in report
        assert "== Scan Summary ==" in report
        assert "== Critical Findings ==" in report
        # 'records' is True in args, so its export function should be called
        assert "== DNS Records ==" in report
        # 'whois' is True, but we haven't mocked an export_func, so it should be skipped
        assert "WHOIS" not in report

    def test_txt_output_to_file(self, sample_scan_data):
        """
        Verifies that the TXT report is correctly written to a file.
        """
        test_dispatch_table = {
            "records": {"data_key": "records_info", "export_func": lambda data: "== DNS Records =="},
        }

        mock_file = mock_open()
        with (
            patch("builtins.open", mock_file),
            patch("modules.output.txt.export_txt_summary", return_value=""),
            patch("modules.output.txt.export_txt_critical_findings", return_value=""),
        ):
            txt_output.output(sample_scan_data, output_path="/fake/report.txt", dispatch_table=test_dispatch_table)

        mock_file.assert_called_once_with("/fake/report.txt", "w", encoding="utf-8")

        # Verify the content written to the file
        written_content = "".join(call.args[0] for call in mock_file().write.call_args_list)
        assert "Zone-Poker Report for: example.com" in written_content
        assert "== DNS Records ==" in written_content


class TestCsvOutput:
    """Unit tests for the CSV output module."""

    def test_csv_output_to_console(self, capsys, sample_scan_data):
        """
        Verifies that CSV output is correctly printed to standard output.
        """
        csv_output.output(sample_scan_data)
        captured = capsys.readouterr()
        csv_string = captured.out

        # Check that the section for the module with data is present
        assert "DNS Records" in csv_string
        assert "1.2.3.4" in csv_string

        # Check that the section for the module with no data is absent
        assert "Zone Transfer (AXFR)" not in csv_string

    def test_csv_output_to_file(self, sample_scan_data):
        """
        Verifies that CSV output is correctly written to a file.
        """
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            csv_output.output(sample_scan_data, output_path="/fake/report.csv")

        mock_file.assert_called_once_with("/fake/report.csv", "w", encoding="utf-8", newline="")

        # Verify the content written to the file
        written_content = "".join(call.args[0] for call in mock_file().write.call_args_list)
        assert "DNS Records" in written_content
        assert "1.2.3.4" in written_content
        assert "Zone Transfer (AXFR)" not in written_content


class TestHtmlOutput:
    """Unit tests for the HTML output module."""

    def test_html_output_to_console(self, capsys, sample_scan_data):
        """
        Verifies that HTML output is correctly printed to standard output.
        """
        html_output.output(sample_scan_data)
        captured = capsys.readouterr()
        html_string = captured.out

        # Perform basic checks on the HTML content
        assert "<!DOCTYPE html>" in html_string
        assert "DNS Intelligence Report for: example.com" in html_string, "The main title is missing from the HTML report."

        # Check that the section for the module with data is present
        assert "DNS Records" in html_string
        assert "1.2.3.4" in html_string

        # Check that the section for the module with no data is absent
        assert "DNS Blocklist (DNSBL) Check" not in html_string

    def test_html_output_to_file(self, sample_scan_data):
        """
        Verifies that HTML output is correctly written to a file.
        """
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            html_output.output(sample_scan_data, output_path="/fake/report.html")

        mock_file.assert_called_once_with("/fake/report.html", "w", encoding="utf-8")

        # Verify the content written to the file
        written_content = "".join(call.args[0] for call in mock_file().write.call_args_list)
        assert "<!DOCTYPE html>" in written_content
        assert "DNS Intelligence Report for: example.com" in written_content
        assert "DNS Records" in written_content
        assert "DNS Blocklist (DNSBL) Check" not in written_content


@patch("modules.output._base.MODULE_DISPATCH_TABLE", MOCK_DISPATCH_TABLE)
class TestXmlOutput:
    """Unit tests for the XML output module."""

    def test_xml_output_to_console(self, capsys, simple_scan_data):
        """
        Verifies that XML output is correctly printed to standard output.
        """
        # Run the output function without an output_path
        xml_output.output(simple_scan_data)
        captured = capsys.readouterr()

        # Parse the captured stdout content as XML
        root = ET.fromstring(captured.out)

        # Assert that the core data and the module with results are present
        assert root.tag == "scan_results"
        assert root.find("domain").text == "example.com"
        assert root.find("dns_info/A").text == "1.2.3.4"

        # Assert that keys with no data or not in the dispatch table are excluded
        assert root.find("whois_info") is None
        assert root.find("some_other_internal_data") is None

    def test_xml_output_to_file(self, simple_scan_data):
        """
        Verifies that XML output is correctly written to a file.
        """
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            xml_output.output(simple_scan_data, output_path="/fake/report.xml")

        # Ensure the file was opened correctly
        mock_file.assert_called_once_with("/fake/report.xml", "w", encoding="utf-8")

        # Verify the content written to the file
        written_content = "".join(call.args[0] for call in mock_file().write.call_args_list)
        root = ET.fromstring(written_content)

        # Assert that the core data and the module with results are present
        assert root.tag == "scan_results"
        assert root.find("domain").text == "example.com"
        assert root.find("dns_info/A").text == "1.2.3.4"

        # Assert that keys with no data or not in the dispatch table are excluded
        assert root.find("whois_info") is None
        assert root.find("some_other_internal_data") is None

    def test_xml_output_excludes_modules_with_errors(self, capsys, simple_scan_data):
        """
        Verifies that modules containing a top-level 'error' key are excluded
        from the XML output.
        """
        # Add a module's data that contains an error
        simple_scan_data["reputation_info"] = {
            "error": "API key not found",
            "some_data": "this should not be included",
        }

        xml_output.output(simple_scan_data)
        root = ET.fromstring(capsys.readouterr().out)

        assert root.find("reputation_info") is None


@patch("modules.output._base.MODULE_DISPATCH_TABLE", MOCK_DISPATCH_TABLE)
class TestJsonOutput:
    """Unit tests for the JSON output module."""

    def test_json_output_to_console(self, capsys, simple_scan_data):
        """
        Verifies that JSON output is correctly printed to standard output.
        """
        # Run the output function without an output_path
        json_output.output(simple_scan_data)
        captured = capsys.readouterr()

        # Parse the captured stdout content as JSON
        output_data = json.loads(captured.out)

        # Assert that the core data and the module with results are present
        assert output_data["domain"] == "example.com"
        assert "dns_info" in output_data
        assert output_data["dns_info"]["A"] == ["1.2.3.4"]

        # Assert that keys with no data or not in the dispatch table are excluded
        assert "whois_info" not in output_data
        assert "some_other_internal_data" not in output_data

    def test_json_output_to_file(self, simple_scan_data):
        """
        Verifies that JSON output is correctly written to a file.
        """
        mock_file = mock_open()
        with patch("builtins.open", mock_file):
            json_output.output(simple_scan_data, output_path="/fake/report.json")

        # Ensure the file was opened correctly
        mock_file.assert_called_once_with("/fake/report.json", "w", encoding="utf-8")

        # Verify the content written to the file
        written_content = "".join(call.args[0] for call in mock_file().write.call_args_list)
        output_data = json.loads(written_content)

        assert output_data["domain"] == "example.com"
        assert "dns_info" in output_data
        assert "whois_info" not in output_data

    def test_json_output_excludes_modules_with_errors(self, capsys, simple_scan_data):
        """
        Verifies that modules containing a top-level 'error' key are excluded
        from the JSON output.
        """
        # Add a module's data that contains an error
        simple_scan_data["reputation_info"] = {
            "error": "API key not found",
            "some_data": "this should not be included",
        }

        json_output.output(simple_scan_data)
        json_string = capsys.readouterr().out
        output_data = json.loads(json_string)

        assert "reputation_info" not in output_data
