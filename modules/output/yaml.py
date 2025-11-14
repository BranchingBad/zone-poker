#!/usr/bin/env python3
"""
Zone-Poker - YAML Output Module
"""

from typing import Any, Dict, Optional

import yaml
from ._base import get_export_data, write_output


class NoTupleDumper(yaml.Dumper):
    """A custom YAML dumper that represents tuples as standard lists."""

    def represent_tuple(self, data):
        return self.represent_sequence("tag:yaml.org,2002:seq", data)


# Add the custom representer to our Dumper class
NoTupleDumper.add_representer(tuple, NoTupleDumper.represent_tuple)


def output(all_data: Dict[str, Any], output_path: Optional[str] = None):
    """
    Generates and prints a clean YAML report to standard output or a file.
    """
    export_data = get_export_data(all_data)

    yaml_string = yaml.dump(export_data, Dumper=NoTupleDumper, default_flow_style=False, sort_keys=False)

    write_output(yaml_string, output_path, "YAML")
