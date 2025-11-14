"""
Pytest shared fixtures for Zone-Poker.
"""

# Sample data that mimics the structure of real scan results.
SAMPLE_SCAN_DATA = {
    "domain": "example.com",
    "scan_timestamp": "2025-11-14T21:15:18Z",
    "dns_info": {"A": ["1.2.3.4"]},
    "whois_info": {},  # This key has empty data and should be excluded.
    "some_other_internal_data": "this should not be in the report",
}

# We mock the dispatch table to control which keys are recognized as
# official module data keys. This isolates the test from the main dispatch table.
MOCK_DISPATCH_TABLE = {
    "dns": {"data_key": "dns_info"},
    "whois": {"data_key": "whois_info"},
    "ssl": {"data_key": "ssl_info"},
    "reputation": {"data_key": "reputation_info"},
}
