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
    # The `[dev]` part installs extra tools for testing, linting, and formatting.
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

### Validating the Package Build
Before submitting a pull request, especially if you've made changes to `pyproject.toml` or file structures, it's a good practice to verify that the package builds correctly and includes all necessary files. This process mimics the `validate-package` job in our CI pipeline.
    1.  **Build the package:**
        ```bash
        # Ensure you have the 'build' package installed (pip install build)
        python -m build
        ```
        This will create a `dist` directory with a `.whl` file.

    2.  **Create a separate test environment:**
        ```bash
        # Create a new virtual environment outside your project directory
        python3 -m venv /tmp/zone-poker-test-env
        source /tmp/zone-poker-test-env/bin/activate
        ```

    3.  **Install the built package:**
        ```bash
        # Install the wheel you just built along with dev dependencies
        pip install "dist/zone_poker-*.whl[dev]"
        ```

    4.  **Run the tests from the new environment.** If all tests pass, it confirms that all modules and data files (like `takeover_fingerprints.json`) were correctly included in the package.

-   **Separation of Concerns**: The project maintains a strict separation between data gathering (analysis) and data presentation (display/output).
    -   **Analysis Modules (`modules/analysis/`)**: These modules should *only* contain the logic for gathering and processing data. They must not contain any `print()` statements or `rich` components. Their sole responsibility is to perform a task and return a data dictionary.
    -   **Display Module (`modules/display.py`)**: This module is responsible for all user-facing console output using the `rich` library.
        -   **Console Display**: Display functions (e.g., `display_dns_records_table`) should be decorated with `@console_display_handler`. They must **return** a `rich` renderable object (like a `Table` or `Panel`) instead of printing it. The orchestrator handles the printing.
    -   **Text Export Module (`modules/export_txt.py`)**: This module contains all the logic for formatting data for the plain text (`.txt`) report.
    -   **Output Modules (`modules/output/`)**: These modules (`json.py`, `csv.py`, etc.) handle the final formatting for non-table console output and file exports.

-   **Adding a New Analysis Module**: To add a new module, you'll typically need to:
    1.  **Analysis Function**: Create your analysis function in a new file under `modules/analysis/`. This function should perform the analysis and return a dictionary of results.
    2.  **Display Function**: In `modules/display.py`, create a corresponding display function (e.g., `display_my_module`). It must be decorated with `@console_display_handler` and **return** a `rich` renderable object (like a `Table` or `Panel`).
    3.  **TXT Export Functions**: In `modules/export_txt.py`, create functions for the plain text export:
        - A private formatter `_format_my_module_txt(data: dict) -> List[str]` that contains the formatting logic.
        - A public `export_txt_my_module(data: dict) -> str` function that calls the `_create_report_section` helper with your new formatter.
    4.  **Dispatch Table Entry**: In `modules/dispatch_table.py`, add an entry to the `MODULE_DISPATCH_TABLE`. This connects your module to the orchestrator and should include:
        - `data_key`: The key for storing results (e.g., `my_module_info`).
        - `analysis_func`: The analysis function you created.
        - `display_func`: The `rich` display function.
        - `export_func`: The text export function.
        - `description`: A short message shown to the user when the module runs.
        - `dependencies`: A list of other modules that must run first (if any).
    5.  **Command-Line Argument**: In `modules/dispatch_table.py`, add an `arg_info` dictionary to your module's entry. The argument parser will pick it up automatically.
    6.  **Unit Tests**: Write unit tests for your new analysis function in the `tests/` directory.
    7.  **Documentation**: Update the `README.md` to include the new module's command-line flag and description in the "Analysis Modules" table.

#### Adding a New Output Format
To add a new console or file output format (e.g., `yaml`):
    1.  **Create a Formatter**: In `modules/output/`, create a new file (e.g., `yaml.py`) with a function like `format_yaml(data: dict) -> str` that converts the data dictionary into a string.
    2.  **Update the Handler**: In `modules/export.py`, import your new function and add a case for it in the `handle_output` function.
    3.  **Update the Parser**: In `modules/parser_setup.py`, add your new format's name to the `choices` list for the `--output` argument.
    4.  **Update Documentation**: Add the new format to the `README.md` in the "Output Formats" section.

---

## Release Process (For Maintainers)

This project uses a CI/CD pipeline to automate releases to PyPI. The process is triggered by pushing a new version tag to the `main` branch.

1.  **Ensure `main` is Ready**: Make sure the `main` branch is stable, all tests are passing, and it contains all the changes you want to include in the release.

2.  **Update the Version**: Bump the version number in `pyproject.toml`. Follow Semantic Versioning.
    ```toml
    # pyproject.toml
    [project]
    version = "1.0.8" # <-- Update this
    ```

3.  **Commit the Version Change**: Commit the change to `pyproject.toml` directly to the `main` branch.
    ```bash
    git add pyproject.toml
    git commit -m "chore(release): Bump version to 1.0.8"
    git push origin main
    ```

4.  **Create and Push a Git Tag**: Create a git tag that matches the version in `pyproject.toml`, prefixed with a `v`.
    ```bash
    git tag v1.0.8
    git push origin v1.0.8
    ```

5.  **Verify the Release**: Pushing the tag will trigger the `publish-to-pypi` job in the CI workflow. You can monitor its progress in the "Actions" tab on GitHub. Once it completes successfully, the new version will be live on PyPI.

## Code of Conduct

All contributors are expected to adhere to our Code of Conduct. Please be respectful and constructive in all interactions.

---
*This document is actively maintained. If you find any instructions to be outdated, please open an issue or a pull request.*