#!/usr/bin/env python3
"""
Zone-Poker - XML Output Module
"""
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Union

from ..config import console
from ..dispatch_table import MODULE_DISPATCH_TABLE

def _to_xml(parent: ET.Element, data: Union[Dict, List, Any], key: str = "item"):
    """
    Recursively converts a Python data structure to XML elements.
    """
    if isinstance(data, dict):
        for k, v in data.items():
            # Create a sub-element for the dictionary key
            sub_element = ET.SubElement(parent, k)
            _to_xml(sub_element, v, k)
    elif isinstance(data, list):
        for item in data:
            # For lists, create elements with the same name as the parent key
            sub_element = ET.SubElement(parent, key)
            _to_xml(sub_element, item, key)
    else:
        # Assign the value as the text content of the parent element
        parent.text = str(data)

def output(all_data: Dict[str, Any]):
    """
    Prints the scan data to the console in XML format.
    """
    root = ET.Element("scan_results")

    # Add top-level domain and timestamp info
    domain_el = ET.SubElement(root, "domain")
    domain_el.text = all_data.get("domain")
    timestamp_el = ET.SubElement(root, "scan_timestamp")
    timestamp_el.text = all_data.get("scan_timestamp")

    # Iterate through modules and add their data
    for module_name, config in MODULE_DISPATCH_TABLE.items():
        data_key = config["data_key"]
        if data_key in all_data and all_data[data_key]:
            module_data = all_data[data_key]
            module_element = ET.SubElement(root, data_key)
            _to_xml(module_element, module_data, data_key)

    # Pretty print the XML
    ET.indent(root, space="  ")
    xml_string = ET.tostring(root, encoding="unicode")
    console.print(xml_string)