#!/usr/bin/env python3
"""
Zone-Poker - TXT Output Module
"""
import builtins
from datetime import datetime
from typing import Dict, Any, Optional

from modules.dispatch_table import MODULE_DISPATCH_TABLE
from modules.export_txt import (
    export_txt_summary,
    export_txt_critical_findings,
)


def output(all_data: Dict[str, Any], output_path: Optional[str] = None):
    """
    Generates and prints a comprehensive TXT report to standard output or a file.
    """
    domain = all_data.get("domain", "report")
    args = all_data.get("args_namespace")

    report_content = [
        f"Zone-Poker Report for: {domain}",
        f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        export_txt_critical_findings(all_data),
        export_txt_summary(all_data),
    ]

    for module_name, details in MODULE_DISPATCH_TABLE.items():
        if getattr(args, module_name, False) or getattr(args, "all", False):
            if export_func := details.get("export_func"):
                module_data = all_data.get(details["data_key"], {})
                report_content.append(export_func(module_data))

    final_report = "\n\n".join(report_content)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(final_report)
    else:
        builtins.print(final_report)
