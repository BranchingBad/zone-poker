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

    # Install the project in editable mode with development dependencies
    pip install -e .[dev]
    ```

3.  **Make your changes**. Please adhere to the existing code style.

4.  **Add or update tests**.
    - If you're adding a new feature (like an analysis module), please include unit tests in the `tests/` directory.
    - If you're fixing a bug, add a test that catches the bug to prevent regressions.

5.  **Ensure all tests pass** before submitting your changes.
    ```bash
    pytest
    ```

6.  **Write clear commit messages**. We follow the Conventional Commits specification. This helps us automatically generate changelogs.
    -   `feat(analysis): Add new module for CAA record checking`
    -   `fix(display): Correctly format output for empty results`
    -   `docs(readme): Update usage examples`
    -   `test(orchestrator): Add test for module dependency resolution`

7.  **Push to your fork** and submit a pull request to the `main` branch of the original repository. In your pull request description, please explain the changes and link to any relevant issues.

## Development Guidelines

-   **Adding a New Analysis Module**: To add a new module, you'll typically need to:
    1.  Create the analysis function in a new file under `modules/analysis/`.
    2.  Create a corresponding display function in `modules/display.py`.
    3.  Add an entry to the `MODULE_DISPATCH_TABLE` in `modules/dispatch_table.py`, linking the module name, functions, dependencies, and command-line flag.
    4.  Write a unit test for your new analysis function in the `tests/` directory.

## Code of Conduct

All contributors are expected to adhere to our Code of Conduct. Please be respectful and constructive in all interactions.