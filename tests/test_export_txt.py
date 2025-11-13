import pytest
from typing import Dict, Any, List
import datetime

# Import the private formatter functions we want to test
from modules.export_txt import (
    _format_records_txt,
    _format_security_audit_txt,
    _format_smtp_txt,
    _format_http_headers_txt,
    _format_ptr_txt,
    _format_zone_txt,
    _format_whois_txt,
    _format_subdomain_takeover_txt,
    _format_cloud_enum_txt,
    _format_mail_txt,
    _format_nsinfo_txt,
    _format_reputation_txt,
    _format_port_scan_txt,
    _format_dnsbl_check_txt,
    _format_propagation_txt,
    _format_tech_txt,
    _format_osint_txt,
    _format_ssl_txt,
    _format_open_redirect_txt,
)
from modules.export_txt import _format_geolocation_txt
from modules.export_txt import _format_security_txt_txt

# --- Fixtures for Test Data ---


@pytest.fixture
def dns_records_data() -> Dict[str, List[Dict[str, Any]]]:
    """Provides sample DNS records data for TXT export testing."""
    return {
        "A": [{"value": "1.2.3.4"}],
        "MX": [{"value": "mail.example.com", "priority": 10}],
        "TXT": [{"value": "v=spf1 -all"}],
    }


@pytest.fixture
def security_audit_data_weak() -> Dict[str, List[Dict[str, str]]]:
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
def smtp_data() -> Dict[str, Any]:
    """Provides sample SMTP analysis data."""
    return {
        "mail.example.com": {
            "banner": "220 mail.example.com ESMTP",
            "starttls": "Supported",
        },
        "alt.mail.example.com": {"error": "Connection timed out"},
    }


@pytest.fixture
def http_headers_data() -> Dict[str, Any]:
    """Provides sample HTTP headers data."""
    return {
        "final_url": "https://example.com",
        "analysis": {
            "Strict-Transport-Security": {
                "status": "Strong",
                "value": "max-age=31536000",
            },
            "X-Frame-Options": {"status": "Missing"},
        },
        "recommendations": ["Implement X-Frame-Options..."],
    }


@pytest.fixture
def zone_data_vulnerable() -> Dict[str, Any]:
    """Provides sample vulnerable zone transfer data."""
    return {
        "summary": "Vulnerable (Zone Transfer Successful)",
        "servers": {
            "ns1.example.com": {
                "status": "Successful",
                "record_count": 120,
            }
        },
    }


@pytest.fixture
def whois_data() -> Dict[str, Any]:
    """Provides sample WHOIS data."""
    return {
        "domain_name": "EXAMPLE.COM",
        "registrar": "Test Registrar",
        "creation_date": "2020-01-01T00:00:00",
        "emails": "admin@example.com",
    }


@pytest.fixture
def takeover_data_vulnerable() -> Dict[str, Any]:
    """Provides sample vulnerable subdomain takeover data."""
    return {
        "vulnerable": [
            {
                "subdomain": "test.example.com",
                "service": "S3",
                "cname_target": "test.s3.amazonaws.com",
            }
        ]
    }


@pytest.fixture
def cloud_enum_data() -> Dict[str, Any]:
    """Provides sample cloud enumeration data."""
    return {
        "s3_buckets": [
            {"url": "http://assets.example.com.s3.amazonaws.com", "status": "public"}
        ],
        "azure_blobs": [
            {"url": "https://example.blob.core.windows.net", "status": "forbidden"}
        ],
    }


@pytest.fixture
def mail_data() -> Dict[str, Any]:
    """Provides sample email security data."""
    return {
        "spf": {"raw": "v=spf1 -all", "all_policy": "-all"},
        "dmarc": {"raw": "v=DMARC1; p=reject;", "p": "reject"},
    }


@pytest.fixture
def nsinfo_data() -> Dict[str, Any]:
    """Provides sample nameserver info data."""
    return {
        "ns1.example.com": {
            "ips": ["1.1.1.1"],
            "asn_description": "CLOUDFLARENET",
        },
        "dnssec": "Enabled",
    }


@pytest.fixture
def reputation_data() -> Dict[str, Any]:
    """Provides sample IP reputation data."""
    return {
        "1.2.3.4": {
            "abuseConfidenceScore": 90,
            "totalReports": 150,
            "lastReportedAt": "2023-10-27T10:00:00+00:00",
        }
    }


@pytest.fixture
def port_scan_data() -> Dict[str, Any]:
    """Provides sample open port data."""
    return {"1.2.3.4": [80, 443], "2.3.4.5": [22]}


@pytest.fixture
def dnsbl_data_listed() -> Dict[str, Any]:
    """Provides sample DNSBL data where an IP is listed."""
    return {
        "listed_ips": [
            {
                "ip": "1.2.3.4",
                "listed_on": ["spamhaus.org", "proofpoint.com"],
            }
        ]
    }


@pytest.fixture
def propagation_data() -> Dict[str, Any]:
    """Provides sample propagation data."""
    return {
        "Google": {"ips": ["1.2.3.4"]},
        "Cloudflare": {"ips": ["1.2.3.4", "1.2.3.5"]},
        "OpenDNS": {"error": "Timeout"},
    }


@pytest.fixture
def tech_data() -> Dict[str, Any]:
    """Provides sample technology detection data."""
    return {"technologies": ["Nginx", "React"], "server": "Nginx"}


@pytest.fixture
def osint_data() -> Dict[str, Any]:
    """Provides sample OSINT data."""
    return {
        "subdomains": ["blog.example.com", "shop.example.com"],
        "passive_dns": [
            {"hostname": "example.com", "ip": "1.2.3.4", "last_seen": "2023-01-01"}
        ],
    }


@pytest.fixture
def ssl_data() -> Dict[str, Any]:
    """Provides sample SSL data."""
    return {
        "subject": "CN=example.com",
        "issuer": "C=US, O=Let's Encrypt, CN=R3",
        "valid_from": datetime.datetime(2023, 1, 1).timestamp(),
        "valid_until": datetime.datetime(2024, 1, 1).timestamp(),
        "sans": ["example.com", "www.example.com"],
    }


@pytest.fixture
def open_redirect_data() -> Dict[str, Any]:
    """Provides sample open redirect data."""
    return {
        "vulnerable_urls": [{"url": "http://a.com", "redirects_to": "http://b.com"}]
    }


@pytest.fixture
def geolocation_data() -> Dict[str, Any]:
    """Provides sample geolocation data."""
    return {
        "1.1.1.1": {"country": "Australia", "city": "Sydney", "isp": "Cloudflare"},
        "8.8.8.8": {
            "country": "United States",
            "city": "Mountain View",
            "isp": "Google LLC",
        },
    }


@pytest.fixture
def security_txt_data_found() -> Dict[str, Any]:
    """Provides sample security.txt data with multiple contacts."""
    return {
        "found": True,
        "url": "https://example.com/security.txt",
        "parsed": {
            "Contact": [
                "mailto:security@example.com",
                "tel:+1-555-555-5555",
            ],
            "Expires": "2025-12-31T23:59:59Z",
        },
    }


@pytest.fixture
def security_txt_data_not_found() -> Dict[str, Any]:
    """Provides sample security.txt data for a not-found case."""
    return {"found": False}


# --- Test Cases ---


def test_format_records_txt_with_data(dns_records_data):
    """Tests that _format_records_txt correctly formats various record types."""
    result = _format_records_txt(dns_records_data)
    result_str = "\n".join(result)

    assert "[A]" in result_str
    assert "  - 1.2.3.4" in result_str
    assert "[MX]" in result_str
    assert "  - mail.example.com (Priority: 10)" in result_str
    assert "[TXT]" in result_str
    assert "  - v=spf1 -all" in result_str


def test_format_records_txt_empty():
    """Tests _format_records_txt with no data."""
    result = _format_records_txt({})
    assert result == ["No DNS records found."]


def test_format_security_audit_txt_with_findings(security_audit_data_weak):
    """Tests that security audit findings are grouped by severity."""
    result = _format_security_audit_txt(security_audit_data_weak)
    result_str = "\n".join(result)

    assert "[Critical Severity Findings]" in result_str
    assert "Finding: Subdomain Takeover" in result_str
    assert "Recommendation: Remove dangling DNS records." in result_str
    assert "[High Severity Findings]" in result_str
    assert "Finding: Missing DMARC Record" in result_str


def test_format_security_audit_txt_no_findings():
    """Tests the security audit formatter when no issues are found."""
    result = _format_security_audit_txt({"findings": []})
    assert result == ["All security checks passed."]


def test_format_smtp_txt_with_data(smtp_data):
    """Tests the SMTP formatter with both success and error data."""
    result = _format_smtp_txt(smtp_data)
    result_str = "\n".join(result)

    assert "  - mail.example.com" in result_str
    assert "Banner: 220 mail.example.com ESMTP" in result_str
    assert "STARTTLS: Supported" in result_str
    assert "  - alt.mail.example.com: Error - Connection timed out" in result_str


def test_format_http_headers_txt_with_data(http_headers_data):
    """Tests the HTTP headers formatter."""
    result = _format_http_headers_txt(http_headers_data)
    result_str = "\n".join(result)

    assert "Final URL: https://example.com" in result_str
    assert "Strict-Transport-Security: Strong - Value: max-age=31536000" in result_str
    assert "X-Frame-Options: Missing" in result_str
    assert "Recommendations:" in result_str
    assert "• Implement X-Frame-Options..." in result_str


def test_format_ptr_txt_with_data():
    """Tests the PTR formatter with data."""
    data = {"1.2.3.4": "rev.example.com", "8.8.8.8": "dns.google"}
    result = _format_ptr_txt(data)
    assert len(result) >= 2
    assert "  - 1.2.3.4          -> rev.example.com" in result


def test_format_ptr_txt_empty():
    """Tests the PTR formatter with no data."""
    result = _format_ptr_txt({})
    assert result == ["No PTR records found."]


def test_format_zone_txt_vulnerable(zone_data_vulnerable):
    """Tests the zone transfer formatter for a vulnerable case."""
    result = _format_zone_txt(zone_data_vulnerable)
    result_str = "\n".join(result)
    assert "Overall Status: Vulnerable (Zone Transfer Successful)" in result_str
    assert "ns1.example.com: Successful" in result_str
    assert "Record Count: 120" in result_str


def test_format_whois_txt(whois_data):
    """Tests the WHOIS formatter."""
    result = _format_whois_txt(whois_data)
    result_str = "\n".join(result)
    assert "Domain Name         : EXAMPLE.COM" in result_str
    assert "Registrar           : Test Registrar" in result_str


def test_format_subdomain_takeover_txt_vulnerable(takeover_data_vulnerable):
    """Tests the subdomain takeover formatter with a vulnerable finding."""
    result = _format_subdomain_takeover_txt(takeover_data_vulnerable)
    result_str = "\n".join(result)
    assert "Found 1 potential subdomain takeovers:" in result_str
    assert "Subdomain: test.example.com" in result_str


def test_format_subdomain_takeover_txt_not_vulnerable():
    """Tests the subdomain takeover formatter with no findings."""
    result = _format_subdomain_takeover_txt({"vulnerable": []})
    assert result == ["No potential subdomain takeovers found."]


def test_format_cloud_enum_txt_with_data(cloud_enum_data):
    """Tests the cloud enumeration formatter."""
    result = _format_cloud_enum_txt(cloud_enum_data)
    result_str = "\n".join(result)
    assert "Discovered S3 Buckets:" in result_str
    assert "http://assets.example.com.s3.amazonaws.com (Status: public)" in result_str
    assert "Discovered Azure Blob Containers:" in result_str
    assert "https://example.blob.core.windows.net (Status: forbidden)" in result_str


def test_format_mail_txt(mail_data):
    """Tests the email security formatter."""
    result = _format_mail_txt(mail_data)
    result_str = "\n".join(result)
    assert "[SPF]" in result_str
    assert "raw" in result_str
    assert "[DMARC]" in result_str
    assert "p" in result_str


def test_format_nsinfo_txt(nsinfo_data):
    """Tests the nameserver info formatter."""
    result = _format_nsinfo_txt(nsinfo_data)
    result_str = "\n".join(result)
    assert "ns1.example.com" in result_str
    assert "IP(s): 1.1.1.1" in result_str
    assert "ASN: CLOUDFLARENET" in result_str
    assert "DNSSEC: Enabled" in result_str


def test_format_reputation_txt(reputation_data):
    """Tests the IP reputation formatter."""
    result = _format_reputation_txt(reputation_data)
    result_str = "\n".join(result)
    assert "1.2.3.4: Score: 90" in result_str
    assert "Reports: 150" in result_str
    assert "Last Reported: 2023-10-27" in result_str


def test_format_port_scan_txt(port_scan_data):
    """Tests the open port scan formatter."""
    if not any(port_scan_data.values()):
        port_scan_data = {}
    result = _format_port_scan_txt(port_scan_data)
    result_str = "\n".join(result)
    assert "Open Ports Found" in result_str
    assert "  - 1.2.3.4: [80, 443]" in result_str
    assert "  - 2.3.4.5: 22" in result


def test_format_dnsbl_check_txt(dnsbl_data_listed):
    """Tests the DNSBL formatter with a listed IP."""
    result = _format_dnsbl_check_txt(dnsbl_data_listed)
    result_str = "\n".join(result)
    assert "Found 1 IP(s) on DNS blocklists" in result_str
    assert "IP Address: 1.2.3.4" in result_str
    assert "Listed on: spamhaus.org, proofpoint.com" in result_str


def test_format_propagation_txt(propagation_data):
    """Tests the propagation formatter."""
    result = _format_propagation_txt(propagation_data)
    result_str = "\n".join(result)
    assert "Google              : 1.2.3.4" in result_str
    assert "Cloudflare          : 1.2.3.4, 1.2.3.5" in result_str
    assert "OpenDNS             : Timeout" in result_str


def test_format_tech_txt(tech_data):
    """Tests the technology detection formatter."""
    result = _format_tech_txt(tech_data)
    result_str = "\n".join(result)
    assert "Technologies        : Nginx, React" in result_str
    assert "Server              : Nginx" in result_str


def test_format_osint_txt(osint_data):
    """Tests the OSINT formatter."""
    result = _format_osint_txt(osint_data)
    result_str = "\n".join(result)
    assert "Subdomains:" in result_str
    assert "  - blog.example.com" in result_str
    assert "Passive DNS:" in result_str
    assert "example.com -> 1.2.3.4 (Last: 2023-01-01)" in result_str


def test_format_ssl_txt(ssl_data):
    """Tests the SSL/TLS formatter."""
    result = _format_ssl_txt(ssl_data)
    result_str = "\n".join(result)
    assert "Subject: CN=example.com" in result_str
    assert "Valid From: 2023-01-01 00:00:00" in result_str
    assert "Subject Alternative Names:" in result_str


def test_format_open_redirect_txt(open_redirect_data):
    """Tests the open redirect formatter."""
    result = _format_open_redirect_txt(open_redirect_data)
    result_str = "\n".join(result)
    assert "Found 1 potential open redirects:" in result_str
    assert "Vulnerable URL: http://a.com" in result_str
    assert "Redirects To:   http://b.com" in result_str


def test_format_security_txt_found(security_txt_data_found):
    """Tests the security.txt formatter with found data."""
    result = _format_security_txt_txt(security_txt_data_found)
    result_str = "\n".join(result)

    assert "Found at: https://example.com/security.txt" in result_str
    assert "Contact             : mailto:security@example.com" in result_str
    assert "Contact             : tel:+1-555-555-5555" in result_str
    assert "Expires             : 2025-12-31T23:59:59Z" in result_str


def test_format_security_txt_not_found(security_txt_data_not_found):
    """Tests the security.txt formatter when the file is not found."""
    result = _format_security_txt_txt(security_txt_data_not_found)
    assert result == ["No security.txt file found at standard locations."]


def test_format_security_txt_found_empty():
    """Tests the security.txt formatter when the file is found but empty."""
    result = _format_security_txt_txt(
        {"found": True, "url": "https://a.com", "parsed": {}}
    )
    assert "File was empty or could not be parsed" in "\n".join(result)


def test_format_geolocation_txt(geolocation_data):
    """Tests the geolocation formatter."""
    result = _format_geolocation_txt(geolocation_data)
    result_str = "\n".join(result)
    assert "1.1.1.1" in result_str
    assert "Sydney, Australia" in result_str
    assert "Cloudflare" in result_str
    assert "8.8.8.8" in result_str
    assert "Mountain View, United States" in result_str
    assert "Google LLC" in result_str
    assert "IP Address" in result[0]
    assert "Location" in result[0]
