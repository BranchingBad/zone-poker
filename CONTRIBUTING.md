# Contributing to Zone-Poker

First off, thank you for considering contributing to Zone-Poker! It's people like you that make open-source software such a great community. We welcome any and all contributions, from bug reports and feature suggestions to new analysis modules.

## How Can I Contribute?

### Reporting Bugs

If you encounter a bug, please [open an issue](https://github.com/BranchingBad/zone-poker/issues) on our GitHub repository. When you report a bug, please include:

- Your operating system name and version.
- The version of Zone-Poker you are using (`zone-poker --version`).
- Detailed steps to reproduce the bug.
- Any relevant error messages or logs. Using the `--verbose` flag can provide helpful details.

### Suggesting Enhancements

If you have an idea for a new feature or an improvement to an existing one, please open an issue to start a discussion. This allows us to align on the proposal before you invest a lot of time in development. We're especially interested in ideas for new analysis modules!

### Submitting Pull Requests

If you'd like to contribute code, we'd love to have your help! Please follow these steps:

1.  **Fork the repository** and create your branch from `main`.

2.  **Set up your development environment**. We recommend using a virtual environment.
    ```bash
    # Clone your fork
    git clone https://github.com/YOUR_USERNAME/zone-poker.git
    cd zone-poker

    # Create and activate a virtual environment (optional but recommended)
    python3 -m venv venv
    source venv/bin/activate

    # Install the project in editable mode with development dependencies.
    # The `[dev]` part installs extra tools for testing and linting, like pytest and flake8.
    pip install -e .[dev]
    ```

3.  **(Optional but Recommended) Set up pre-commit hooks.** This will automatically run linters and formatters on your code before you commit, ensuring it meets our style guidelines.
    ```bash
    pre-commit install
    ```

4.  **Make your changes**. Please adhere to the existing code style (see Code Style section below).

5.  **Add or update tests**.
    - If you're adding a new feature (like an analysis module), please include unit tests in the `tests/` directory.
    - If you're fixing a bug, add a test that catches the bug to prevent regressions.

6.  **Ensure all tests pass** before submitting your changes.
    ```bash
    pytest
    ```

7.  **Update documentation if needed**. If you've added a new module or changed a command-line argument, please update the `README.md` file to reflect this.

8.  **Write clear commit messages**. We follow the Conventional Commits specification. This helps us automatically generate changelogs.
    -   `feat(analysis): Add new module for CAA record checking`
    -   `fix(display): Correctly format output for empty results`
    -   `docs(readme): Update usage examples`
    -   `test(orchestrator): Add test for module dependency resolution`

9.  **Push to your fork** and submit a pull request to the `main` branch of the original repository. In your pull request description, please explain the changes and link to any relevant issues.

## Development Guidelines

-   **Code Style**: We use `black` for code formatting and `flake8` for linting to maintain a consistent style. If you set up `pre-commit` as suggested, these checks will run automatically. Otherwise, you can run them manually:
    ```bash
    black .
    flake8 .
    ```

-   **Separation of Concerns**: The project maintains a strict separation between data gathering (analysis) and data presentation (display/output).
    -   **Analysis Modules (`modules/analysis/`)**: These modules should *only* contain the logic for gathering and processing data. They must not contain any `print()` statements or `rich` components. Their sole responsibility is to perform a task and return a data dictionary.
    -   **Display Module (`modules/display.py`)**: This module is responsible for all user-facing console output using the `rich` library.
        -   **Console Display**: Display functions (e.g., `display_dns_records_table`) should be decorated with `@console_display_handler`. They must **return** a `rich` renderable object (like a `Table` or `Panel`) instead of printing it. The orchestrator handles the printing.
    -   **Text Export Module (`modules/export_txt.py`)**: This module contains all the logic for formatting data for the plain text (`.txt`) report.

-   **Adding a New Analysis Module**: To add a new module, you'll typically need to:
    1.  Create the analysis function in a new file under `modules/analysis/`.
    2.  Create a corresponding display function (e.g., `display_my_module`) in `modules/display.py`. It must be decorated with `@console_display_handler` and return a `rich` object.
    3.  Create two functions for the TXT export in `modules/export_txt.py`:
        - A private formatter `_format_my_module_txt(data: dict) -> List[str]` that handles the actual formatting logic.
        - A public `export_txt_my_module(data: dict) -> str` function that calls the `_create_report_section` helper with your new formatter.
    4.  Add an entry to the `MODULE_DISPATCH_TABLE` in `modules/dispatch_table.py`. This dictionary entry connects your new module to the orchestrator and should include:
        - `data_key`: The key for storing results (e.g., `my_module_info`).
        - `analysis_func`: The analysis function you created.
        - `display_func`: The `rich` display function.
        - `export_func`: The text export function.
        - `description`: A short message shown to the user when the module runs.
        - `dependencies`: A list of other modules that must run first (if any).
        - `arg_info`: A dictionary defining the command-line flag (e.g., `--my-module`).
    5.  Write a unit test for your new analysis function in the `tests/` directory.
    6.  Update the `README.md` to include the new module's command-line flag and description.

-   **Adding a New Output Format**:
    -   **For Console Output (e.g., XML, CSV):**
        1.  Create a new file in `modules/output/` (e.g., `xml.py`).
        2.  Inside this file, create a function `output(all_data: Dict[str, Any])` that takes the complete scan data and **prints** it to the console.
        3.  Add the name of your new format (e.g., `'xml'`) to the `choices` list for the `--output` argument in `modules/parser_setup.py`.
    -   **For File Export (e.g., HTML, Markdown):**
        1.  Create a new file in `modules/output/` (e.g., `html.py`).
        2.  Inside this file, create a function `output(all_data: Dict[str, Any])`. This function should:
            - Retrieve the target file path from `all_data['export_filepath']`.
            - Generate the report content.
            - Write the content to the specified file path.
            - It should **not** print to the console.
        3.  Add a new command-line argument (e.g., `--html-file`) in `modules/parser_setup.py` to enable your new export format.
        4.  Update the `export_reports` function in `modules/export.py` to recognize and handle your new argument.

## Code of Conduct

All contributors are expected to adhere to our Code of Conduct. Please be respectful and constructive in all interactions.