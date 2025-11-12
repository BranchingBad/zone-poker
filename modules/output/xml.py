#!/usr/bin/env python3
"""
Zone-Poker - XML Output Module
"""
import builtins
from typing import Dict, Any
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom

from rich.console import Console

console = Console()


def _dict_to_xml(parent: Element, data: Dict[str, Any]):
    """Recursively convert a dictionary to XML elements."""
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, dict):
            child = SubElement(parent, key)
            _dict_to_xml(child, value)
        elif isinstance(value, list):
            for item in value:
                child = SubElement(parent, key)
                if isinstance(item, dict):
                    _dict_to_xml(child, item)
                else:
                    child.text = str(item)
        else:
            child = SubElement(parent, key)
            child.text = str(value)


def output(all_data: Dict[str, Any]):
    """
    Generates and prints an XML report to standard output.
    """
    root = Element("scan_results")
    _dict_to_xml(root, all_data)

    # Pretty print the XML
    rough_string = tostring(root, "utf-8")
    reparsed = minidom.parseString(rough_string)
    pretty_xml = reparsed.toprettyxml(indent="  ")

    # Using builtins.print to send to stdout for redirection.
    builtins.print(pretty_xml)
