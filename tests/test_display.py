import pytest
from rich.panel import Panel
from rich.table import Table

# Assume display_security_txt is in modules.display, even if not in context
from modules.display import display_security_txt

# --- Fixtures for security.txt Test Data ---


@pytest.fixture
def security_txt_found_data() -> dict:
    """Provides sample data for a found and parsed security.txt file."""
    return {
        "found": True,
        "url": "https://example.com/.well-known/security.txt",
        "parsed": {
            "Contact": "mailto:security@example.com",
            "Expires": "2025-12-31T23:59:59Z",
        },
    }


@pytest.fixture
def security_txt_not_found_data() -> dict:
    """Provides sample data for when a security.txt file is not found."""
    return {"found": False, "url": None, "parsed": {}}


@pytest.fixture
def security_txt_found_empty_data() -> dict:
    """Provides sample data for a found but empty/unparseable security.txt file."""
    return {
        "found": True,
        "url": "https://example.com/security.txt",
        "parsed": {},
    }


# --- Test Cases for display_security_txt ---


def test_display_security_txt_found(security_txt_found_data):
    """Tests that a found security.txt file is displayed correctly in a table."""
    result = display_security_txt(security_txt_found_data, quiet=False)

    assert isinstance(result, Panel)
    assert "Found at https://example.com/.well-known/security.txt" in result.title
    assert isinstance(result.renderable, Table)
    # This is a bit of an indirect check, but verifies the table has rows
    assert len(result.renderable.rows) == 2


def test_display_security_txt_not_found(security_txt_not_found_data):
    """Tests the display output when no security.txt file is found."""
    result = display_security_txt(security_txt_not_found_data, quiet=False)

    assert isinstance(result, Panel)
    assert "No security.txt file found" in str(result.renderable)


def test_display_security_txt_found_empty(security_txt_found_empty_data):
    """Tests the display output for a found but empty security.txt file."""
    result = display_security_txt(security_txt_found_empty_data, quiet=False)

    assert isinstance(result, Panel)
    assert "Found at https://example.com/security.txt" in result.title
    assert "File was empty or could not be parsed" in result.renderable.caption


def test_display_security_txt_quiet_mode(security_txt_found_data):
    """Tests that nothing is returned when in quiet mode."""
    result = display_security_txt(security_txt_found_data, quiet=True)
    assert result is None
