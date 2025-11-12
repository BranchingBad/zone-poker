#!/usr/bin/env python3
"""
Zone-Poker - HTML Output Module
"""
from typing import Dict, Any
from rich.console import Console
from io import StringIO
from datetime import datetime
from ..dispatch_table import MODULE_DISPATCH_TABLE
from ..display import display_summary, display_critical_findings
from ..config import console

CSS_STYLE = """
<style>
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        line-height: 1.6;
        color: #e0e0e0;
        background-color: #121212;
        margin: 0;
        padding: 0;
    }
    .container {
        max-width: 1200px;
        margin: 20px auto;
        padding: 0 20px;
    }
    .header {
        background-color: #1e1e1e;
        padding: 20px;
        border-bottom: 1px solid #333;
        text-align: center;
    }
    .header h1 {
        margin: 0;
        font-size: 2.5em;
        color: #bb86fc;
    }
    .header p {
        margin: 5px 0 0;
        color: #888;
    }
    pre {
        background-color: #1e1e1e;
        border: 1px solid #333;
        border-radius: 5px;
        padding: 15px;
        white-space: pre-wrap;
        word-wrap: break-word;
        font-family: 'Menlo', 'DejaVu Sans Mono', 'Consolas', 'Courier New', monospace;
        font-size: 0.95em;
    }
    /* Rich-specific styles */
    .rich-panel-title {
        font-style: italic;
        color: #03dac6;
    }
    .rich-table-caption {
        color: #888;
        font-style: italic;
    }
</style>
"""


def output(all_data: Dict[str, Any]):
    """
    Generates and prints an HTML report of the scan data.

    This function re-uses the rich display functions to generate HTML content
    by capturing the output of a temporary console.
    """
    domain = all_data.get("domain", "Unknown Domain")

    # Use an in-memory text buffer to capture rich output
    string_io = StringIO()
    record_console = Console(file=string_io, record=True, width=120)

    # Display critical findings and summary first by calling the display functions
    # and printing their returned renderable to our recording console.
    if critical_renderable := display_critical_findings(all_data, quiet=False):
        record_console.print(critical_renderable)
        record_console.print()
    if summary_renderable := display_summary(all_data, quiet=False):
        record_console.print(summary_renderable)
        record_console.print()

    # Loop through the dispatch table to render each module's output
    for module_name, config in MODULE_DISPATCH_TABLE.items():
        data_key = config["data_key"]
        display_func = config.get("display_func")

        if (data := all_data.get(data_key)) and display_func:
            if renderable := display_func(data, quiet=False):
                record_console.print(renderable)
                record_console.print()  # Add spacing between sections

    # Generate the HTML from the recorded output, but without the default full-page structure
    rich_html_body = record_console.export_html(
        code_format="<pre><code>{code}</code></pre>"
    )

    # Construct the final HTML with our custom header and styles
    html_output = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Zone-Poker Report for {domain}</title>
{CSS_STYLE}
</head>
<body>
    <div class="header">
        <h1>DNS Intelligence Report</h1>
        <p>Target: {domain}</p>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    <div class="container">
        {rich_html_body}
    </div>
</body>
</html>"""

    # Check if a file path was provided in the arguments
    args = all_data.get("args_namespace")
    html_filepath = getattr(args, "html_file", None)

    if html_filepath:
        try:
            with open(html_filepath, "w", encoding="utf-8") as f:
                f.write(html_output)
            console.print(f"\n[green]✓ HTML report saved to:[/] {html_filepath}")
        except Exception as e:
            console.print(
                f"[bold red]Error saving HTML report to {html_filepath}: {e}[/bold red]"
            )
    else:
        print(html_output)
