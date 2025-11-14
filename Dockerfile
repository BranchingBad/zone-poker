# Dockerfile

# --- Builder Stage ---
# This stage builds the Python wheels for the project and its dependencies.
FROM python:3.11-slim-bookworm as builder

# Set the working directory
WORKDIR /app

# [FIX] Accept a build argument for the application version
ARG APP_VERSION=0.0.0-local

# Install build dependencies
RUN pip install --no-cache-dir build pip-tools

# Copy dependency definition files
COPY pyproject.toml poetry.lock* pyproject.lock* requirements.txt* ./

# Generate and install dependencies into a temporary location
# This creates a layer that is cached as long as dependencies don't change
RUN pip-compile --output-file=requirements.txt pyproject.toml && \
    pip install --no-cache-dir --prefix="/install" -r requirements.txt

# Copy the rest of the application source code
COPY . .

# [FIX] Set the environment variable for setuptools-scm to use the provided version
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${APP_VERSION}

# Build the wheel for the project itself and add it to the /wheels directory
RUN python -m build --wheel --outdir /wheels


# --- Final Stage ---
# This stage creates the final, slim production image.
FROM python:3.11-slim-bookworm as final

WORKDIR /app

# Copy the installed dependencies and the project wheel from the builder stage
COPY --from=builder /install /usr/local
COPY --from=builder /wheels /wheels

# Install the project wheel
RUN pip install --no-cache-dir /wheels/zone_poker-*.whl

# Set the entrypoint for the container
ENTRYPOINT ["zone-poker"]