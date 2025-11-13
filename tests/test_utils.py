import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from modules.utils import (
    is_valid_domain,
    get_parent_zone,
    join_txt_chunks,
    _format_rdata,
    _parse_spf_record,
    get_desktop_path,
)


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("example.com", True),
        ("sub.example.co.uk", True),
        ("a-b.c", False),  # .c is not a widely recognized TLD by default tldextract
        ("-example.com", False),
        ("example.com-", False),
        ("example..com", False),  # Double dot
        ("example", False),  # No TLD
        ("example.com.", True),  # FQDN with trailing dot
        (".example.com", False),
        ("", False),  # Empty string
        (None, False),  # None value
        ("a" * 63 + ".com", True),  # Max label length
        ("a" * 64 + ".com", False),  # Exceeds max label length
        ("xn--bcher-kva.com", True),  # Punycode (IDN)
        (123, False),  # Not a string
    ],
)
def test_is_valid_domain(domain, expected):
    """Tests the is_valid_domain function with various inputs."""
    assert is_valid_domain(domain) 

@pytest.mark.parametrize(
    "domain, expected",
    [
        ("sub.example.com", "example.com"),
        ("www.sub.example.co.uk", "example.co.uk"),
        ("example.com", None),
        ("localhost", None),
        ("co.uk", None),  # Should be treated as a TLD
        ("co.uk", None),  # Should be treated as a TLD
    ],
)
def test_get_parent_zone(domain, expected):
    """Tests the get_parent_zone function."""
    assert get_parent_zone(domain) == expected


def test_join_txt_chunks():
    """Tests the join_txt_chunks function."""
    assert join_txt_chunks(["one", "two"]) == "onetwo"
    assert join_txt_chunks([]) == ""
    assert join_txt_chunks(["single"]) == "single"


def test_format_rdata():
    """Tests the _format_rdata function for various record types."""
    # Mock base rdata object
    mock_rdata = MagicMock()

    # Test A record
    mock_rdata.to_text.return_value = "1.2.3.4"
    assert _format_rdata("A", mock_rdata.to_text(), ttl=300, name="a.com") == {
        "ttl": 300,
        "name": "a.com",
        "value": "1.2.3.4",
    }

    # Test MX record
    mock_mx = MagicMock()
    mock_mx.name = "mx.com"
    mock_mx.ttl = 300
    mock_mx.exchange = "mail.example.com"
    mock_mx.preference = 10
    assert _format_rdata("MX", mock_mx, ttl=300, name="mx.com") == {
        "ttl": 300,
        "name": "mx.com",
        "value": "mail.example.com",
        "priority": 10,
    }

    # Test SOA record
    mock_soa = MagicMock()
    mock_soa.name = "soa.com"
    mock_soa.ttl = 3600
    mock_soa.mname = "ns1.example.com"
    mock_soa.rname = "admin.example.com"
    mock_soa.serial = 2022010101
    assert _format_rdata("SOA", mock_soa, ttl=3600, name="soa.com") == {
        "ttl": 3600,
        "name": "soa.com",
        "value": "ns1.example.com",
        "rname": "admin.example.com",
        "serial": 2022010101,
    }


def test_parse_spf_record():
    """Tests the _parse_spf_record helper function."""
    spf_string = "v=spf1 ip4:1.2.3.4 include:_spf.google.com ~all"
    parsed = _parse_spf_record(spf_string)
    assert parsed["version"] == "v=spf1"
    assert parsed["mechanisms"]["ip4"] == ["1.2.3.4"]
    assert parsed["mechanisms"]["include"] == ["_spf.google.com"]
    assert parsed["all_policy"] == "~all"


@patch("sys.platform", "win32")
@patch("pathlib.Path.exists", return_value=True)
@patch("pathlib.Path.is_dir", return_value=True)
def test_get_desktop_path_windows(mock_is_dir, mock_exists):
    """Tests get_desktop_path on a mocked Windows system."""
    home_path = Path.home()
    expected_desktop = home_path / "Desktop"
    assert get_desktop_path() == expected_desktop


@patch("sys.platform", "darwin")
@patch("pathlib.Path.exists", return_value=True)
@patch("pathlib.Path.is_dir", return_value=True)
def test_get_desktop_path_macos(mock_is_dir, mock_exists):
    """Tests get_desktop_path on a mocked macOS system."""
    home_path = Path.home()
    expected_desktop = home_path / "Desktop"
    assert get_desktop_path() == expected_desktop


@patch("sys.platform", "linux")
@patch("os.environ", {"XDG_DESKTOP_DIR": "/home/user/Desktop"})
@patch("pathlib.Path.exists", return_value=True)
@patch("pathlib.Path.is_dir", return_value=True)
def test_get_desktop_path_linux_xdg(mock_is_dir, mock_exists):
    """Tests get_desktop_path on Linux with XDG_DESKTOP_DIR set."""
    expected_desktop = Path("/home/user/Desktop")
    assert get_desktop_path() == expected_desktop


@patch("sys.platform", "linux")
@patch("os.environ", {})  # No XDG var
@patch("os.environ", {})  # No XDG var
@patch("pathlib.Path.exists")
@patch("pathlib.Path.is_dir")
def test_get_desktop_path_fallback(mock_is_dir, mock_exists):
    """Tests the fallback mechanism of get_desktop_path."""
    home_path = Path.home()
    desktop_path = home_path / "Desktop"

    # Simulate Desktop path not existing
    def side_effect():
        return False

    mock_exists.side_effect = side_effect

    # Should fall back to the home directory
    assert get_desktop_path() == home_path
