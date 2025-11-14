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

    # Install development dependencies from the lock file.
    pip install -r requirements.txt
    # Install the project in editable mode.
    pip install -e .
    ```

3.  **(Optional but Recommended) Set up pre-commit hooks.** This will automatically run linters and formatters on your code before you commit, ensuring it meets our style guidelines.
    ```bash
    pre-commit install
    ```

4.  **Make your changes**. Please adhere to the existing code style (see Code Style section below).
    - When you commit, the pre-commit hooks will automatically format your code, check for issues, and even validate your dependencies.
    - If a hook modifies a file (like `ruff format` or `compile-requirements`), you will need to `git add` the changed files and commit again.

    - **Code Style**: This project uses `ruff` for ultra-fast code formatting, import sorting, and linting. The pre-commit hooks will automatically enforce this style.

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
    -   `feat(security): Add support for parsing security.txt files`

9.  **Push to your fork** and submit a pull request to the `main` branch of the original repository. In your pull request description, please explain the changes and link to any relevant issues. Our `release-drafter` bot will automatically categorize your PR for the release notes based on its label (e.g., `bug`, `feature`).

## Development Guidelines

### Managing Dependencies

This project uses `pip-tools` to manage dependencies via a `requirements.txt` lock file. This ensures that every developer and the CI environment uses the exact same package versions.

**To add or update a dependency:**

1.  **Edit `pyproject.toml`**: Add or change the desired package version range in the `[project.dependencies]` or `[project.optional-dependencies.dev]` sections.

2.  **Regenerate the lock file**: Run the `pip-compile` command to update `requirements.txt` based on your changes.
    ```bash
    # This command compiles both main and dev dependencies into the lock file
    pip-compile --extra=dev --output-file=requirements.txt pyproject.toml
    ```

3.  **Commit both files**: Add both `pyproject.toml` and the regenerated `requirements.txt` to your commit. The `compile-requirements` pre-commit hook will automatically run this for you if it detects changes in `pyproject.toml`. You will just need to stage the updated `requirements.txt`.
    > **Why?** Committing the lock file ensures that every developer, as well as the CI pipeline, uses the exact same versions of all dependencies. This prevents "it works on my machine" issues. Our CI includes a `validate-lockfile` job that will fail if `requirements.txt` is not kept in sync with `pyproject.toml`.
    > If you have pre-commit hooks installed, this process is automated. The hook will regenerate `requirements.txt` for you and ask you to stage the changes.

4.  **Install the updated packages**: Refresh your local virtual environment with the new set of dependencies.
    ```bash
    pip install -r requirements.txt
    ```

### Understanding Configuration Precedence

The tool loads settings with a clear priority order, which is important to remember when testing:
1.  **Defaults**: The application's built-in default values.
2.  **Config File**: Values from a `.yaml` or `.json` file specified with `--config`. These override the defaults.
3.  **CLI Arguments**: Any arguments passed on the command line (e.g., `--timeout 30`). These override everything else and have the final say.

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
    1.  **Create an Output Module**: In `modules/output/`, create a new file (e.g., `yaml.py`) with an `output(all_data: dict, output_path: str)` function. This function will handle both formatting the data and writing to a file or standard output.
    2.  **Update `__init__.py`**: Add your new module to `modules/output/__init__.py` to make it easily importable.
    3.  **Update Main Script**: In your main script, import the new output module and add it to the output handling logic (e.g., a dictionary of output functions) and the `argparse` choices for the `--output` flag.
    4.  **Add Dependencies**: If your new module has dependencies, add them to the `requirements.txt` file.
    5.  **Update Documentation**: Add the new format to the `README.md` in the "Output Formats" section.

---

## Code of Conduct

All contributors are expected to follow our Code of Conduct. Please be respectful and constructive in all your interactions within the project.

---

## Release Process (For Maintainers)

The release process is highly automated. Maintainers publish a release on GitHub, which automatically creates a version tag. This tag triggers the CI/CD pipeline to build the package, publish it to PyPI, and attach the built artifacts to the GitHub Release.

For detailed instructions on how to perform a release, maintainers should refer to the `RELEASING.md` file.

---
*This document is actively maintained. If you find any instructions to be outdated, please open an issue or a pull request.*
