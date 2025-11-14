#!/usr/bin/env python3
"""
Zone-Poker - Utilities Module
Contains helper functions used across different modules.
"""
import os  # noqa: F401
import sys
from pathlib import Path
from typing import Any, Dict

import tldextract  # Import the tldextract library


def get_desktop_path() -> Path:
    """
    Get the user's desktop directory path in a cross-platform way.
    Checks for Windows, macOS, and Linux environments (including XDG standards).
    If the desktop path cannot be determined, it safely falls back to the user's
    home directory.
    Returns:
        A Path object representing the absolute path to the desktop or home directory.
    """
    home = Path.home()

    if sys.platform == "win32":
        desktop = home / "Desktop"
    elif sys.platform == "darwin":  # macOS
        desktop = home / "Desktop"
    else:
        # Linux: Check for XDG user dir, then 'Desktop', then fallback to home
        desktop = Path(os.environ.get("XDG_DESKTOP_DIR", home / "Desktop"))

    if not desktop.exists() or not desktop.is_dir():
        desktop = home  # Fallback to home directory

    return desktop


def join_txt_chunks(chunks: list[str]) -> str:
    """Join multi-chunk TXT records (quoted strings) into a single string"""
    return "".join(chunks)


def get_parent_zone(domain: str) -> str | None:
    """Get the parent zone for a domain (for DS record lookup)"""
    # Use tldextract to reliably get the registered domain (e.g., 'example.co.uk')
    # which serves as the parent zone for DS lookups.
    try:
        extracted = tldextract.extract(domain)
        if extracted.subdomain:
            return extracted.top_domain_under_public_suffix
        return None  # It's already a root domain, no parent zone to check
    except (ValueError, AttributeError):
        return None


# --- Helper Functions Moved from Analysis.py ---


def _format_rdata(
    rtype: str, rdata: Any, *, ttl: int, name: str = ""
) -> Dict[str, Any]:
    """Format a single dnspython rdata object into a standardized dictionary."""
    record_info: Dict[str, Any] = {"ttl": ttl, "name": str(name)}
    if rtype == "MX":
        record_info.update(
            {
                "value": str(rdata.exchange),
                "priority": rdata.preference,
            }
        )
    elif rtype == "SRV":
        record_info.update(
            {
                "value": str(rdata.target),
                "priority": rdata.priority,
                "weight": rdata.weight,
                "port": rdata.port,
            }
        )
    elif rtype == "SOA":
        record_info.update(
            {
                "value": str(rdata.mname),
                "rname": str(rdata.rname),
                "serial": rdata.serial,
            }
        )
    elif rtype == "DS":
        record_info.update(
            {
                "value": rdata.digest.hex().upper(),
                "key_tag": rdata.key_tag,
                "algorithm": rdata.algorithm,
                "digest_type": rdata.digest_type,
            }
        )
    elif rtype == "DNSKEY":
        record_info.update(
            {
                "value": rdata.key,
                "flags": rdata.flags,
                "protocol": rdata.protocol,
                "algorithm": rdata.algorithm,
            }
        )
    elif rtype == "NAPTR":
        record_info.update(
            {
                "value": str(rdata.replacement),
                "order": rdata.order,
                "preference": rdata.preference,
                "flags": rdata.flags.decode("utf-8", "ignore"),
                "service": rdata.service.decode("utf-8", "ignore"),
                "regexp": rdata.regexp.decode("utf-8", "ignore"),
            }
        )
    elif rtype == "CAA":
        tag = rdata.tag.decode("utf-8", "ignore")
        value = rdata.value.decode("utf-8", "ignore")
        if tag == "contactemail":
            tag = "iodef"
            value = f"mailto:{value}"
        record_info.update(
            {
                "value": value,
                "tag": tag,
                "flags": rdata.flags,
            }
        )
    elif rtype == "TXT":
        record_info["value"] = join_txt_chunks(
            [t.decode("utf-8", "ignore") for t in rdata.strings]
        )
    else:
        record_info["value"] = str(rdata)
    return record_info


def _parse_spf_record(spf_record: str) -> Dict[str, Any]:
    """Helper to parse an SPF record string."""
    parts = spf_record.split()
    analysis = {"raw": spf_record, "mechanisms": {}}
    if parts:
        analysis["version"] = parts[0]
        for part in parts[1:]:
            if part.startswith(
                ("redirect=", "include:", "a:", "mx:", "ip4:", "ip6:", "exists:")
            ):
                key, _, value = part.partition(":")
                key = key.lstrip("+-~?")
                analysis["mechanisms"].setdefault(key, []).append(value)
            elif part in ("-all", "~all", "+all", "?all"):
                analysis["all_policy"] = part  # type: ignore
    return analysis


def _parse_dmarc_record(dmarc_record: str) -> Dict[str, Any]:
    """Helper to parse a DMARC record string."""
    analysis = {"raw": dmarc_record}
    if "v=DMARC1" not in dmarc_record:
        analysis["error"] = "Not a valid DMARC record."
        return analysis

    for part in dmarc_record.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            analysis[key.strip()] = value.strip()
    return analysis


def is_valid_domain(domain: str) -> bool:
    """
    Check if a given string is a syntactically valid domain name.
    This is a basic check and does not guarantee the domain exists or is resolvable.
    """
    if not isinstance(domain, str) or not domain:
        return False

    if domain.startswith("."):
        return False

    # A domain can end with a dot (FQDN)
    if domain.endswith("."):
        domain = domain[:-1]

    # Overall length check
    if len(domain) > 253:
        return False

    # Use tldextract for robust parsing
    extracted = tldextract.extract(domain)

    # A valid domain must have a domain part and a known TLD/suffix.
    # It must not be a private/internal TLD.
    if not extracted.domain or not extracted.suffix or extracted.is_private:
        return False

    # A valid public TLD cannot be all-numeric.
    if extracted.suffix.isdigit():
        return False

    # Check each part (label) of the domain
    labels = (extracted.subdomain + "." + extracted.domain).strip(".").split(".")
    for label in labels:
        if not (0 < len(label) <= 63) or label.startswith("-") or label.endswith("-"):
            return False

    return True
