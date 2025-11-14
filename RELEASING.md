# Release Process

This project uses a highly automated CI/CD pipeline to manage releases. The `release-drafter` action automatically prepares a draft of the release notes as pull requests are merged into the `main` branch. The release itself is triggered by publishing this draft release on GitHub.

The process is as follows:

1.  **Review the Draft Release**:
    -   Navigate to the **Releases** page of the GitHub repository.
    -   You will find a draft release at the top of the page with a title like "vX.X.X". This draft contains a changelog of all changes merged into `main` since the last release.
    -   Review the categorized list of changes to ensure it's accurate.

2.  **Determine the New Version Number**:
    -   Based on the changes in the draft, decide on the new version number following Semantic Versioning (e.g., `v1.1.0` for new features, `v1.0.1` for bug fixes).
    -   This project uses `setuptools-scm`, so the version is derived from the Git tag. You do **not** need to manually update the version in `pyproject.toml`.

3.  **Publish the Release**:
    -   Click **Edit** on the draft release.
    -   In the "Tag version" and "Release title" fields, replace the placeholder version with the new version number you decided on (e.g., `v1.1.0`).
    -   Optionally, add any high-level release summary to the top of the description.
    -   Click the **Publish release** button.

4.  **Verify the Automated CI/CD**:
    -   Publishing the release automatically creates the new version tag.
    -   This tag push triggers the `publish-to-pypi` and `release` jobs in the CI workflow.
    -   You can monitor their progress in the "Actions" tab on GitHub.
    -   Once the jobs complete, the new version will be live on PyPI, and the built package files (wheel and sdist) will be attached to the GitHub Release.
