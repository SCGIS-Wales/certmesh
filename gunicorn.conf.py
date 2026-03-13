"""Gunicorn production configuration for certmesh API."""

import multiprocessing
import os

# Server socket
bind = os.environ.get("CM_API_BIND", "0.0.0.0:8000")

# Worker processes
workers = int(os.environ.get("CM_API_WORKERS", 2 * multiprocessing.cpu_count() + 1))
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000

# Timeouts
timeout = int(os.environ.get("CM_API_TIMEOUT", "120"))
graceful_timeout = 30
keepalive = 5

# Worker recycling (prevent memory leaks)
max_requests = int(os.environ.get("CM_API_MAX_REQUESTS", "10000"))
max_requests_jitter = int(os.environ.get("CM_API_MAX_REQUESTS_JITTER", "1000"))

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("CM_API_LOG_LEVEL", "info")

# Preload app for faster worker start (shares memory via copy-on-write)
preload_app = False

# Security: limit request sizes
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190
