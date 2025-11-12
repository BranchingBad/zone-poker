import pytest
import argparse
from unittest.mock import AsyncMock, patch, MagicMock

from modules.orchestrator import _scan_single_domain


@pytest.fixture
def mock_args():
    """Creates a mock argparse.Namespace object."""
    args = argparse.Namespace()
    args.quiet = False
    args.verbose = False
    # Add other default args as needed by your modules
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
@patch("modules.orchestrator.get_module_dispatch_table")
async def test_orchestrator_with_dependencies(mock_table, mock_args):
    """
    Tests that the orchestrator runs modules and their dependencies in the correct order.
    """
    # Use a custom mock table for this test
    mock_table.get.side_effect = {
        "records": {
            "data_key": "records_info",
            "analysis_func": AsyncMock(return_value={"A": []}),
            "display_func": MagicMock(),
            "dependencies": [],
            "description": "...",
        },
        "ptr": {
            "data_key": "ptr_info",
            "analysis_func": AsyncMock(return_value={}),
            "display_func": MagicMock(),
            "dependencies": ["records_info"],
            "description": "...",
        },
    }.get
    mock_table.keys.return_value = ["records", "ptr"]

    # We only ask to run 'ptr', but 'records' should run first as a dependency.
    modules_to_run = ["ptr"]
    mock_table.return_value = {
        "records": {
            "analysis_func": AsyncMock(return_value={"A": []}),
            "display_func": MagicMock(), "dependencies": [], "data_key": "records_info"
        },
        "ptr": {
            "analysis_func": AsyncMock(return_value={}),
            "display_func": MagicMock(), "dependencies": ["records_info"], "data_key": "ptr_info"
        }
    }
    with patch(
        "modules.orchestrator._create_execution_plan", return_value=["records", "ptr"]
    ):
        await _scan_single_domain("example.com", mock_args, modules_to_run)

    mock_table.return_value["records"]["analysis_func"].assert_awaited_once()
    mock_table.return_value["ptr"]["analysis_func"].assert_awaited_once()

    call_kwargs = mock_table.return_value["ptr"]["analysis_func"].call_args.kwargs
    assert "records_info" in call_kwargs


@pytest.mark.asyncio
@patch("modules.orchestrator.get_module_dispatch_table")
async def test_orchestrator_selective_run(mock_table, mock_args):
    """
    Tests that only specified modules are run when there are no dependencies.
    """
    mock_table.get.side_effect = {
        "records": {
            "analysis_func": AsyncMock(),
            "display_func": MagicMock(),
            "dependencies": [],
            "data_key": "records_info",
            "description": "...",
        },
        "whois": {
            "analysis_func": AsyncMock(),
            "display_func": MagicMock(),
            "dependencies": [],
            "data_key": "whois_info",
            "description": "...",
        },
    }.get
    mock_table.keys.return_value = ["records", "whois"]
    mock_table.return_value = {
        "records": {"analysis_func": AsyncMock(), "display_func": MagicMock(), "dependencies": [], "data_key": "records_info"},
        "whois": {"analysis_func": AsyncMock(), "display_func": MagicMock(), "dependencies": [], "data_key": "whois_info"}
    }

    modules_to_run = ["whois"]
    with patch("modules.orchestrator._create_execution_plan", return_value=["whois"]):
        await _scan_single_domain("example.com", mock_args, modules_to_run)

    # 'whois' should be called, but 'records' should not.
    mock_table.return_value["whois"]["analysis_func"].assert_awaited_once()
    mock_table.return_value["records"]["analysis_func"].assert_not_awaited()


@pytest.mark.asyncio
@patch("modules.orchestrator.get_module_dispatch_table")
async def test_orchestrator_quiet_mode(mock_table, mock_args):
    """
    Tests that display functions are NOT called when quiet mode is enabled.
    """
    mock_dispatch = {
        "records": {
            "analysis_func": AsyncMock(return_value={}),
            "display_func": MagicMock(),
            "dependencies": [],
            "data_key": "records_info",
            "description": "...",
        }
    }
    mock_table.return_value = mock_dispatch
    mock_args.quiet = True

    with patch("modules.orchestrator._create_execution_plan", return_value=["records"]):
        await _scan_single_domain("example.com", mock_args, ["records"])

    mock_dispatch["records"]["display_func"].assert_not_called()
