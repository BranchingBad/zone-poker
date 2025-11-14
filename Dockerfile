# --- Builder Stage ---
# This stage builds the Python wheels for the project and its dependencies.
FROM python:3.11-slim-bookworm as builder

# Set the working directory
WORKDIR /app

# Accept a build argument for the application version
ARG APP_VERSION=0.0.0-local

# Install build dependencies
RUN pip install --no-cache-dir build pip-tools

# Copy only the dependency definition source file
COPY pyproject.toml ./

# Generate and install dependencies into a temporary location
RUN pip-compile --output-file=requirements.txt pyproject.toml && \
    pip install --no-cache-dir --prefix="/install" -r requirements.txt

# Copy the rest of the application source code
# (Ensure you have a .dockerignore file)
COPY . .

# Corrected environment variable for setuptools-scm
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${APP_VERSION}

# Build the wheel for the project itself
RUN python -m build --wheel --outdir /wheels


# --- Final Stage ---
# This stage creates the final, slim production image.
FROM python:3.11-slim-bookworm as final

# [SECURITY] Install latest OS security patches first
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# [SECURITY] Create a non-root user and group
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --shell /bin/false --create-home appuser

# Copy the installed dependencies and the project wheel from the builder stage
COPY --from=builder /install /usr/local
COPY --from=builder /wheels /wheels

# Install the wheel and clean up artifacts
RUN pip install --no-cache-dir /wheels/*.whl && \
    rm -rf /wheels

# [SECURITY] Change ownership of the app directory to the new user
# This ensures the non-root user can read/execute the app files.
RUN chown -R appuser:appgroup /app

# [SECURITY] Switch to the non-root user
USER appuser

# Set the entrypoint for the container
ENTRYPOINT ["zone-poker"]