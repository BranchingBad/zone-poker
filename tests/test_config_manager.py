#!/usr/bin/env python3
"""
Unit tests for the Configuration Manager module in Zone-Poker.
"""
import pytest
from unittest.mock import patch

from modules.parser_setup import setup_parser
from modules.config_manager import setup_configuration_and_domains


@pytest.fixture
def parser():
    """Provides a fresh parser for each test."""
    return setup_parser()


def test_cli_only_args(parser):
    """Tests that basic command-line arguments are parsed correctly without a config file."""
    cli_input = ["example.com", "--timeout", "15", "--verbose"]
    with patch("sys.argv", ["zone-poker"] + cli_input):
        args, domains = setup_configuration_and_domains(parser)

    assert args.domain == "example.com"
    assert args.timeout == 15
    assert args.verbose is True
    assert domains == ["example.com"]


def test_config_file_only(parser, tmp_path):
    """Tests loading configuration purely from a YAML file."""
    config_content = """
timeout: 20
export: true
records: true
    """
    config_file = tmp_path / "config.yaml"
    config_file.write_text(config_content)

    cli_input = ["-c", str(config_file), "configdomain.com"]
    with patch("sys.argv", ["zone-poker"] + cli_input):
        args, domains = setup_configuration_and_domains(parser)

    assert args.timeout == 20
    assert args.export is True
    assert args.records is True
    assert domains == ["configdomain.com"]


def test_cli_overrides_config_file(parser, tmp_path):
    """
    Tests that command-line arguments correctly override settings from a config file.
    """
    config_content = """
timeout: 20
verbose: false
export: false
    """
    config_file = tmp_path / "config.yaml"
    config_file.write_text(config_content)

    # CLI args should override all config file values
    cli_input = [
        "example.com",
        "-c",
        str(config_file),
        "--timeout",
        "10",
        "--verbose",
        "--export",
    ]
    with patch("sys.argv", ["zone-poker"] + cli_input):
        args, domains = setup_configuration_and_domains(parser)

    assert args.timeout == 10  # CLI (10) wins over config (20)
    assert args.verbose is True  # CLI flag wins over config (False)
    assert args.export is True  # CLI flag wins over config (False)
    assert domains == ["example.com"]


def test_load_domains_from_file(parser, tmp_path):
    """Tests loading a list of domains from a JSON file via the -f argument."""
    domains_content = '["domain1.com", "domain2.co.uk"]'
    domains_file = tmp_path / "domains.json"
    domains_file.write_text(domains_content)

    cli_input = ["-f", str(domains_file)]
    with patch("sys.argv", ["zone-poker"] + cli_input):
        args, domains = setup_configuration_and_domains(parser)

    assert domains == ["domain1.com", "domain2.co.uk"]
    # Ensure that the positional 'domain' arg is not set
    assert args.domain is None


def test_cli_domain_and_file_input_fails(parser, tmp_path, capsys):
    """
    Tests that providing both a positional domain and a domain file (-f)
    is not allowed by argparse.
    """
    domains_content = '["file-domain.com"]'
    domains_file = tmp_path / "domains.json"
    domains_file.write_text(domains_content)

    cli_input = ["cli-domain.com", "-f", str(domains_file)]
    with patch("sys.argv", ["zone-poker"] + cli_input), pytest.raises(SystemExit):
        args, domains = setup_configuration_and_domains(parser)

    captured = capsys.readouterr()
    assert "not allowed with argument domain" in captured.err


def test_config_file_not_found(parser, capsys):
    """Tests that a clear error is shown if the config file doesn't exist."""
    cli_input = ["-c", "nonexistent.yaml", "example.com"]
    with (
        patch("sys.argv", ["zone-poker"] + cli_input),
        patch("modules.config_manager.console.print") as mock_print,
        pytest.raises(SystemExit),
    ):
        args, domains = setup_configuration_and_domains(parser)

    # Check that our mock print was called with the correct error
    mock_print.assert_called_once()
    assert (
        "Error: Config file 'nonexistent.yaml' not found." in mock_print.call_args[0][0]
    )


def test_domain_file_not_found(parser, capsys):
    """Tests error handling when the domain input file is not found."""
    cli_input = ["-f", "nonexistent.json"]
    with (
        patch("sys.argv", ["zone-poker"] + cli_input),
        patch("modules.config_manager.console.print") as mock_print,
        pytest.raises(SystemExit),
    ):
        args, domains = setup_configuration_and_domains(parser)

    # Check that our mock print was called with the correct error
    mock_print.assert_called_once()
    assert (
        "Error: The domain file 'nonexistent.json' was not found."
        in mock_print.call_args[0][0]
    )


def test_invalid_domain_from_cli(parser, capsys):
    """Tests that an invalid domain from the CLI is caught."""
    cli_input = ["-invalid-domain.com"]
    with patch("sys.argv", ["zone-poker"] + cli_input), pytest.raises(SystemExit):
        args, domains = setup_configuration_and_domains(parser)

    captured = capsys.readouterr()
    # Argparse sees this as an unrecognized argument
    assert "unrecognized arguments: -invalid-domain.com" in captured.err


def test_invalid_domain_in_file(parser, tmp_path, capsys):
    """Tests that an invalid domain within a domain file is caught."""
    domains_content = '["valid.com", "invalid..com"]'
    domains_file = tmp_path / "domains.json"
    domains_file.write_text(domains_content)

    cli_input = ["-f", str(domains_file)]
    with (
        patch("sys.argv", ["zone-poker"] + cli_input),
        patch("modules.config_manager.console.print") as mock_print,
        pytest.raises(SystemExit),
    ):
        args, domains = setup_configuration_and_domains(parser)

    # Check that our mock print was called with the correct error
    mock_print.assert_called_once()
    assert (
        "Error: Invalid domain format 'invalid..com' in file"
        in mock_print.call_args[0][0]
    )


def test_no_domain_provided(parser):
    """
    Tests that the parser exits if no domain or file is provided.
    This is handled by argparse `nargs='?'`, so we just check no domains are returned.
    """
    cli_input = ["--timeout", "10"]  # No domain or -f
    with patch("sys.argv", ["zone-poker"] + cli_input):
        args, domains = setup_configuration_and_domains(parser)

    assert domains == []
    assert args.domain is None


def test_boolean_flag_merging(parser, tmp_path):
    """
    Tests that boolean flags are merged correctly.
    - Config sets `export` to True.
    - CLI does not specify `export`, so the config value should be used.
    """
    config_content = "export: true"
    config_file = tmp_path / "config.yaml"
    config_file.write_text(config_content)

    cli_input = ["-c", str(config_file), "example.com"]
    with patch("sys.argv", ["zone-poker"] + cli_input):
        args, domains = setup_configuration_and_domains(parser)

    assert args.export is True
