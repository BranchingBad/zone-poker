import pytest
import argparse
from unittest.mock import AsyncMock, patch, MagicMock

from modules.orchestrator import run_analysis_modules


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
            "dependencies": ["records"],
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
@patch("modules.orchestrator.MODULE_DISPATCH_TABLE", new_callable=MagicMock)
async def test_orchestrator_with_dependencies(mock_table, mock_args):
    """
    Tests that the orchestrator runs modules and their dependencies in the correct order.
    """
    # Use a custom mock table for this test
    mock_table.items.return_value = {
        "records": {
            "data_key": "records",
            "analysis_func": AsyncMock(return_value={"A": []}),
            "display_func": MagicMock(),
            "dependencies": [],
            "description": "...",
        },
        "ptr": {
            "data_key": "ptr_lookups",
            "analysis_func": AsyncMock(return_value={}),
            "display_func": MagicMock(),
            "dependencies": ["records"],
            "description": "...",
        },
    }.items()
    mock_table.keys.return_value = ["records", "ptr"]

    # We only ask to run 'ptr', but 'records' should run first as a dependency.
    modules_to_run = ["ptr"]
    all_data = await run_analysis_modules(modules_to_run, "example.com", mock_args)

    # Check that both analysis functions were called
    mock_table.items.return_value[0][1]["analysis_func"].assert_awaited_once()
    mock_table.items.return_value[1][1]["analysis_func"].assert_awaited_once()

    # Check that the data from the dependency ('records') was available to the dependent ('ptr')
    # The second argument to the call should be the `all_data` dict containing previous results.
    call_args, _ = mock_table.items.return_value[1][1]["analysis_func"].call_args
    assert "records" in call_args[1]


@pytest.mark.asyncio
@patch("modules.orchestrator.MODULE_DISPATCH_TABLE")
async def test_orchestrator_selective_run(mock_table, mock_args):
    """
    Tests that only the specified modules are run when there are no dependencies.
    """
    mock_table.items.return_value = {
        "records": {
            "analysis_func": AsyncMock(),
            "display_func": MagicMock(),
            "dependencies": [],
            "data_key": "records",
            "description": "...",
        },
        "whois": {
            "analysis_func": AsyncMock(),
            "display_func": MagicMock(),
            "dependencies": [],
            "data_key": "whois",
            "description": "...",
        },
    }.items()
    mock_table.keys.return_value = ["records", "whois"]

    modules_to_run = ["whois"]
    await run_analysis_modules(modules_to_run, "example.com", mock_args)

    # 'whois' should be called, but 'records' should not.
    mock_table.items.return_value[1][1]["analysis_func"].assert_awaited_once()
    mock_table.items.return_value[0][1]["analysis_func"].assert_not_awaited()


@pytest.mark.asyncio
@patch("modules.orchestrator.MODULE_DISPATCH_TABLE")
async def test_orchestrator_quiet_mode(mock_table, mock_args):
    """
    Tests that display functions are NOT called when quiet mode is enabled.
    """
    mock_table.items.return_value = {
        "records": {
            "analysis_func": AsyncMock(return_value={}),
            "display_func": MagicMock(),
            "dependencies": [],
            "data_key": "records",
            "description": "...",
        }
    }.items()
    mock_table.keys.return_value = ["records"]
    mock_args.quiet = True

    await run_analysis_modules(["records"], "example.com", mock_args)

    mock_table.items.return_value[0][1]["display_func"].assert_not_called()
