# =============================================================================
# Stage 1: Build wheel
# =============================================================================
FROM python:3.14-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir build \
    && python -m build --wheel

# =============================================================================
# Stage 2: Production runtime (hardened)
# =============================================================================
FROM python:3.14-slim

# Create non-root user
RUN groupadd -r certmesh \
    && useradd -r -g certmesh -d /app -s /sbin/nologin certmesh \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install application from wheel
COPY --from=builder /build/dist/*.whl .
RUN pip install --no-cache-dir *.whl && rm *.whl

# Writable /tmp for gunicorn worker temp files (read-only root filesystem)
RUN mkdir -p /tmp/certmesh && chown certmesh:certmesh /tmp/certmesh

# Copy gunicorn config for production tuning
COPY gunicorn.conf.py /app/gunicorn.conf.py

# Switch to non-root user
USER certmesh

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["curl", "-f", "http://localhost:8000/healthz"]

# Production entrypoint: gunicorn with uvicorn workers
ENTRYPOINT ["gunicorn", "certmesh.api.app:create_app", \
    "--config", "/app/gunicorn.conf.py", \
    "--factory"]
