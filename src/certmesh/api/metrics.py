"""
certmesh.api.metrics
=====================

Prometheus metrics for the REST API.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# HTTP request metrics
HTTP_REQUESTS_TOTAL = Counter(
    "certmesh_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

HTTP_REQUEST_DURATION = Histogram(
    "certmesh_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# Certificate operation metrics
CERTIFICATE_OPS_TOTAL = Counter(
    "certmesh_certificate_operations_total",
    "Total certificate operations",
    ["provider", "operation", "status"],
)

# Certificate expiry gauge (updated by background task)
CERTIFICATE_EXPIRY_DAYS = Gauge(
    "certmesh_certificate_expiry_days",
    "Days until certificate expiry",
    ["provider", "common_name", "serial"],
)

# Circuit breaker state gauge
CIRCUIT_BREAKER_STATE = Gauge(
    "certmesh_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=open, 2=half_open)",
    ["name"],
)
