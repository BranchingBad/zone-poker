#!/usr/bin/env python3
"""
Zone-Poker - HTML Output Module
"""
import builtins
from typing import Dict, Any, Optional
from ..config import console

from rich.console import Console
from rich.panel import Panel

from modules.dispatch_table import MODULE_DISPATCH_TABLE
from modules.display import display_summary, display_critical_findings


def _render_to_html(renderable: Optional[Panel]) -> str:
    """
    Renders a rich renderable to an HTML string.
    If the renderable is None, returns an empty string.
    """
    if renderable is None:
        return ""
    console = Console(record=True, width=120)
    console.print(renderable)
    return console.export_html(inline_styles=True, code_format="<pre>{code}</pre>")


def output(all_data: Dict[str, Any], output_path: Optional[str] = None):
    """
    Generates and prints a self-contained HTML report to standard output or a file.

    Args:
        all_data: The dictionary containing all scan data.
        output_path: If provided, the output is written to this file path.
    """
    domain = all_data.get("domain", "N/A")
    timestamp = all_data.get("scan_timestamp", "")

    # --- 1. Generate HTML for each component ---
    critical_html = _render_to_html(display_critical_findings(all_data, quiet=False))
    summary_html = _render_to_html(display_summary(all_data, quiet=False))

    module_html_parts = []
    for module_name, details in MODULE_DISPATCH_TABLE.items():
        # Check if the module was run (by checking for its data key)
        if details["data_key"] in all_data:
            data = all_data.get(details["data_key"])
            if display_func := details.get("display_func"):
                renderable = display_func(data, quiet=False)
                module_html_parts.append(_render_to_html(renderable))

    # --- 2. Assemble the final HTML document ---
    html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zone-Poker Report: {domain}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         Helvetica, Arial, sans-serif;
            background-color: #1e1e1e;
            color: #d4d4d4;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
        }}
        h1, h2 {{
            color: #569cd6;
            border-bottom: 1px solid #569cd6;
            padding-bottom: 5px;
        }}
        .report-header {{
            text-align: center;
            margin-bottom: 40px;
        }}
        .report-header p {{
            color: #808080;
        }}
        .module-container {{
            margin-bottom: 30px;
        }}
        /* Rich-exported styles will be inlined, but add a wrapper */
        .rich-panel {{
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <h1>DNS Intelligence Report for: {domain}</h1>
        <p>Generated at: {timestamp}</p>
    </div>

    <!-- Critical Findings -->
    {f'''<div class="module-container">
        {critical_html}
    </div>''' if critical_html else ''}

    <!-- Summary -->
    <div class="module-container">
        <h2>Scan Summary</h2>
        {summary_html}
    </div>

    <!-- Detailed Module Outputs -->
    <div class="module-container">
        <h2>Detailed Analysis</h2>
        {''.join(module_html_parts)}
    </div>

</body>
</html>
"""

    html_content = html_template.strip()
    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        except IOError as e:
            console.print(
                f"[bold red]Error writing HTML file to {output_path}: {e}[/bold red]"
            )
    else:
        builtins.print(html_content)
