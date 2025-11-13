#!/usr/bin/env python3
"""
Unit tests for the output format handlers in Zone-Poker.
"""
import pytest
from modules.export import handle_output


@pytest.fixture
def mock_all_data():
    """Provides a sample `all_data` dictionary for testing output formats."""
    return {
        "domain": "example.com",
        "scan_timestamp": "2025-11-12T20:30:00",
        "args_namespace": {},
        "records_info": {
            "A": [{"value": "1.2.3.4", "ttl": 300, "name": "example.com."}],
            "MX": [
                {
                    "value": "mail.example.com.",
                    "ttl": 600,
                    "name": "example.com.",
                    "priority": 10,
                }
            ],
        },
        "whois_info": {
            "domain_name": "EXAMPLE.COM",
            "registrar": "Test Registrar Inc.",
        },
        "security_info": {
            "findings": [
                {
                    "finding": "DNSSEC Not Enabled",
                    "severity": "Medium",
                    "recommendation": "Enable DNSSEC.",
                }
            ]
        },
    }


def test_handle_output_txt(mock_all_data, capsys):
    """
    Tests that the 'txt' console output format correctly generates and prints
    a text-based report to the console.
    """
    # Call the handler with the 'txt' format. output_path is None for console output.
    handle_output(mock_all_data, "txt", output_path=None)

    captured = capsys.readouterr()
    output = captured.out

    # Check for key components of the TXT report
    assert "DNS Intelligence Report for: example.com" in output
    assert "--- DNS Records ---" in output
    assert "[A]" in output
    assert "1.2.3.4" in output
    assert "--- WHOIS Information ---" in output
    assert "Domain Name         : EXAMPLE.COM" in output
    assert "--- Security Audit ---" in output
    assert "[Medium Severity Findings]" in output
    assert "Finding: DNSSEC Not Enabled" in output
