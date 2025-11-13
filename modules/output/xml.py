#!/usr/bin/env python3
"""
Zone-Poker - XML Output Module
"""
import builtins
from typing import Dict, Any, Optional
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom
from modules.dispatch_table import MODULE_DISPATCH_TABLE
from rich.console import Console

console = Console()


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

    Args:
        all_data: The dictionary containing all scan data.
        output_path: If provided, the output is written to this file path.
    """
    export_data = {
        "domain": all_data.get("domain"),
        "scan_timestamp": all_data.get("scan_timestamp"),
    }

    # Add data from each module, using the data_key from the dispatch table
    for module_name, config in MODULE_DISPATCH_TABLE.items():
        data_key = config["data_key"]
        # Only add data if it exists and is not empty
        if data_key in all_data and all_data[data_key]:
            export_data[data_key] = all_data[data_key]

    root = Element("scan_results")
    _dict_to_xml(root, export_data)

    # Pretty print the XML
    rough_string = tostring(root, "utf-8")
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent="  ")

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(pretty_xml)
        except IOError as e:
            console.print(
                f"[bold red]Error writing XML file to {output_path}: {e}[/bold red]"
            )
    else:
        builtins.print(pretty_xml)
