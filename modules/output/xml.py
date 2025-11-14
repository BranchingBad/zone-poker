#!/usr/bin/env python3
"""
Zone-Poker - XML Output Module
"""

from typing import Any, Dict, Optional
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement, tostring

from ._base import get_export_data, write_output


def _dict_to_xml(parent: Element, data: Dict[str, Any]):
    """Recursively convert a dictionary to XML elements."""
    import re

    for key, value in data.items():
        if value is None:
            continue
        # Sanitize key to be a valid XML tag name
        safe_key = re.sub(r"[^a-zA-Z0-9_]", "_", str(key))
        # XML tags cannot start with a number
        if safe_key and safe_key[0].isdigit():
            safe_key = f"ip_{safe_key}"
        # Skip if the key becomes empty after sanitization
        if not safe_key:
            continue
        if isinstance(value, dict):
            child = SubElement(parent, safe_key)
            _dict_to_xml(child, value)
        elif isinstance(value, list):
            for item in value:
                child = SubElement(parent, safe_key)
                if isinstance(item, dict):
                    _dict_to_xml(child, item)
                else:
                    # Sanitize value to remove invalid XML characters
                    safe_value = re.sub(
                        r"[^\u0009\u000a\u000d\u0020-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]",
                        "",
                        str(item),
                    )
                    child.text = safe_value
        else:
            child = SubElement(parent, safe_key)
            # Sanitize value to remove invalid XML characters
            safe_value = re.sub(
                r"[^\u0009\u000a\u000d\u0020-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]",
                "",
                str(value),
            )
            child.text = safe_value


def output(all_data: Dict[str, Any], output_path: Optional[str] = None):
    """
    Generates and prints an XML report to standard output or a file.
    """
    export_data = get_export_data(all_data)

    root = Element("scan_results")
    _dict_to_xml(root, export_data)

    # Pretty print the XML
    rough_string = tostring(root, "utf-8")
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent="  ")

    write_output(pretty_xml, output_path, "XML")
