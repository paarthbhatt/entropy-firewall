"""Prometheus metrics utilities."""

from __future__ import annotations

from prometheus_client import Counter, Histogram, Gauge, generate_latest


# -- Counters --
REQUESTS_TOTAL = Counter(
    "entropy_requests_total",
    "Total requests processed",
    ["status", "provider"],
)

THREATS_DETECTED = Counter(
    "entropy_threats_detected_total",
    "Total threats detected",
    ["category", "threat_level"],
)

OUTPUT_SANITIZATIONS = Counter(
    "entropy_output_sanitizations_total",
    "Total output sanitization events",
    ["rule"],
)

# -- Histograms --
REQUEST_DURATION = Histogram(
    "entropy_request_duration_seconds",
    "Request processing duration",
    ["endpoint"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

ANALYSIS_DURATION = Histogram(
    "entropy_analysis_duration_ms",
    "Security analysis duration in milliseconds",
    buckets=[0.1, 0.5, 1, 2, 5, 10, 25, 50, 100],
)

# -- Gauges --
PATTERNS_LOADED = Gauge(
    "entropy_patterns_loaded",
    "Number of detection patterns loaded",
)


def get_metrics_text() -> bytes:
    """Generate Prometheus metrics text."""
    return generate_latest()
