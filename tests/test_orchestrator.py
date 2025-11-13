import pytest
import argparse
from unittest.mock import AsyncMock, patch, MagicMock, PropertyMock

from modules.orchestrator import _scan_single_domain, _create_execution_plan


@pytest.fixture
def mock_args():
    """Creates a mock argparse.Namespace object."""
    args = argparse.Namespace()
    args.quiet = False
    args.verbose = False
    # Add other default args as needed by your modules
    args.output = None
    args.timeout = 5
    args.api_keys = {}
    return args


@pytest.fixture
def mock_dispatch_table():
    """
    Provides a simplified, mocked version of the MODULE_DISPATCH_TABLE
    for testing dependency and execution logic.
    """
    return {
        "records": {
            "data_key": "records",
            "analysis_func": AsyncMock(return_value={"A": [{"value": "1.2.3.4"}]}),
            "display_func": MagicMock(),
            "description": "Querying DNS records...",
            "dependencies": [],
        },
        "ptr": {
            "data_key": "ptr_lookups",
            "analysis_func": AsyncMock(return_value={"1.2.3.4": "rev.example.com"}),
            "display_func": MagicMock(),
            "description": "Performing reverse DNS lookups...",
            "dependencies": ["records"],  # noqa: E501
        },
        "whois": {
            "data_key": "whois",
            "analysis_func": AsyncMock(return_value={"registrar": "Test Registrar"}),
            "display_func": MagicMock(),
            "description": "Performing WHOIS lookup...",
            "dependencies": [],
        },
    }


@pytest.mark.asyncio
@patch("modules.orchestrator.MODULE_DISPATCH_TABLE")
async def test_orchestrator_with_dependencies(mock_table, mock_args):
    """
    Tests that the orchestrator runs modules and their dependencies in the correct order.
    """
    # We only ask to run 'ptr', but 'records' should run first as a dependency.
    modules_to_run = ["ptr"]

    # Setup a mock dispatch table that the orchestrator can iterate through
    mock_records_func = AsyncMock(return_value={"A": []})
    mock_ptr_func = AsyncMock(return_value={})
    mock_table.items.return_value = [
        (
            "records",
            {
                "analysis_func": mock_records_func,
                "display_func": MagicMock(),
                "dependencies": [],
                "data_key": "records_info",
                "description": "...",
            },
        ),
        (
            "ptr",
            {
                "analysis_func": mock_ptr_func,
                "display_func": MagicMock(),
                "dependencies": ["records"],
                "data_key": "ptr_info",
                "description": "...",
            },
        ),
    ]

    # The execution plan should correctly identify the order
    with patch(
        "modules.orchestrator._create_execution_plan", return_value=["records", "ptr"]
    ) as mock_plan:
        await _scan_single_domain("example.com", mock_args, modules_to_run)

    mock_plan.assert_called_once_with(modules_to_run)
    mock_records_func.assert_awaited_once()
    mock_ptr_func.assert_awaited_once()

    # Verify that the result of the 'records' module was passed to the 'ptr' module
    call_kwargs = mock_ptr_func.call_args[1]
    assert "records_info" in call_kwargs


@pytest.mark.asyncio
@patch("modules.orchestrator.MODULE_DISPATCH_TABLE")
async def test_orchestrator_selective_run(mock_table, mock_args):
    """
    Tests that only specified modules are run when there are no dependencies.
    """
    mock_records_func = AsyncMock()
    mock_whois_func = AsyncMock()
    mock_table.items.return_value = [
        (
            "records",
            {
                "analysis_func": mock_records_func,
                "display_func": MagicMock(),
                "dependencies": [],
                "data_key": "records_info",
                "description": "...",
            },
        ),
        (
            "whois",
            {
                "analysis_func": mock_whois_func,
                "display_func": MagicMock(),
                "dependencies": [],
                "data_key": "whois_info",
                "description": "...",
            },
        ),
    ]

    modules_to_run = ["whois"]
    with patch("modules.orchestrator._create_execution_plan", return_value=["whois"]):
        await _scan_single_domain("example.com", mock_args, modules_to_run)

    # 'whois' should be called, but 'records' should not.
    mock_whois_func.assert_awaited_once()
    mock_records_func.assert_not_awaited()


@pytest.mark.asyncio
@patch("modules.orchestrator.MODULE_DISPATCH_TABLE")
async def test_orchestrator_quiet_mode(mock_table, mock_args):
    """
    Tests that display functions are NOT called when quiet mode is enabled.
    """
    mock_display_func = MagicMock()
    mock_table.items.return_value = [
        (
            "records",
            {
                "analysis_func": AsyncMock(return_value={}),
                "display_func": mock_display_func,
                "dependencies": [],
                "data_key": "records_info",
                "description": "...",
            },
        )
    ]
    mock_args.quiet = True
    mock_args.output = "table"  # Ensure display logic would normally run

    with patch("modules.orchestrator._create_execution_plan", return_value=["records"]):
        await _scan_single_domain("example.com", mock_args, ["records"])

    mock_display_func.assert_not_called()
