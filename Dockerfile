# --- Stage 1: Builder ---
# This stage builds the Python wheel for the project.
FROM python:3.11-slim as builder

WORKDIR /app

# Install build and wheel dependencies
RUN pip install --no-cache-dir build wheel

# --- Optimized Caching ---
# Copy only the dependency files first. This layer is only invalidated if
# the requirements or project definition change.
COPY pyproject.toml requirements.txt ./

# Download all runtime dependencies as wheels into the /wheels directory.
# This step is cached as long as requirements.txt doesn't change.
RUN pip wheel --wheel-dir=/wheels -r requirements.txt

# Now, copy the rest of the application source code. Changes to source files
# will only invalidate the cache from this point forward.
COPY . .

# Build the wheel for the project itself and add it to the /wheels directory.
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

# Install the project and its dependencies from the local wheels.
# --no-cache-dir reduces image size, and --no-index prevents reaching out to PyPI.
# The glob pattern ensures we install the project wheel along with its dependencies.
RUN pip install --no-cache-dir --no-index --find-links=/wheels "zone-poker"

# Set the entrypoint to the zone-poker executable
ENTRYPOINT ["zone-poker"]

# Add a healthcheck to verify the application is runnable
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["zone-poker", "--version"]

# Default command to run when the container starts (e.g., show help)
CMD ["--help"]
