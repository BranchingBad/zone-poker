# --- Stage 1: Builder ---
# This stage builds the Python wheel for the project.
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir build

# Copy only the file that defines dependencies to leverage Docker layer caching.
# This layer is only invalidated if pyproject.toml changes.
COPY pyproject.toml .

# Build the wheel. This will install dependencies in an isolated environment.
RUN python -m build --wheel --outdir /wheels


# --- Stage 2: Runtime ---
# This is the final, optimized image.
FROM python:3.11-slim as runtime

# Set the working directory in the container
WORKDIR /app

# Create a non-root user for security
RUN useradd --create-home appuser
USER appuser

# Copy the built wheel from the builder stage
COPY --from=builder /wheels /wheels

# Install the wheel. This installs the project and its runtime dependencies.
# --no-cache-dir reduces image size, and --no-index prevents reaching out to PyPI.
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/*.whl

# Set the entrypoint to the zone-poker executable
ENTRYPOINT ["zone-poker"]

# Default command to run when the container starts (e.g., show help)
CMD ["--help"]