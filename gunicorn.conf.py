"""Gunicorn production configuration for certmesh API."""

import multiprocessing
import os
import sys

# Server socket
bind = os.environ.get("CM_API_BIND", "0.0.0.0:8000")

# ---------------------------------------------------------------------------
# Worker processes
# ---------------------------------------------------------------------------
# CM_API_WORKERS controls worker count:
#   "auto" (default) -- 2 x CPU cores + 1 (gunicorn recommended formula)
#   integer          — explicit override (e.g. "4")
#
# In containerised environments, multiprocessing.cpu_count() respects the
# cgroup CPU quota, so "auto" works correctly under resource limits.
_raw_workers = os.environ.get("CM_API_WORKERS", "auto")
if _raw_workers.lower() in ("auto", "0", ""):
    _cpu_count = multiprocessing.cpu_count()
    workers = 2 * _cpu_count + 1
    print(
        f"[gunicorn.conf] Auto-detected {_cpu_count} CPU(s) → {workers} workers",
        file=sys.stderr,
    )
else:
    workers = int(_raw_workers)
    print(f"[gunicorn.conf] Worker count override → {workers} workers", file=sys.stderr)

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

# REL-06: Use tmpfs for worker heartbeat files to avoid disk I/O on container
# overlay filesystems (prevents heartbeat timeout false positives).
worker_tmp_dir = "/dev/shm"

# Security: limit request sizes
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190
