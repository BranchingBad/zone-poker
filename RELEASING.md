# Release Process

This project uses a CI/CD pipeline to automate releases to PyPI. The process is triggered by pushing a new version tag to the `main` branch.

The process is as follows:

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

4.  **Create and Push a Git Tag**: Create a git tag that matches the version in `pyproject.toml`, prefixed with a `v`. The CI workflow includes a step to verify this match.
    ```bash
    git tag v1.0.8
    git push origin v1.0.8
    ```

5.  **Verify the Release**: Pushing the tag will trigger the `publish-to-pypi` job in the CI workflow. You can monitor its progress in the "Actions" tab on GitHub. Once it completes successfully, the new version will be live on PyPI.
