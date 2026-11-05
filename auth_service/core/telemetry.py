"""Telemetry and Prometheus metrics collection system for Auth-as-a-Service.

Provides zero-dependency thread-safe metrics recording and Prometheus text-format exposition.
Tracks authentication events, latency, rate limit triggers, security anomalies, and active sessions.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple


class MetricType:
    """Prometheus metric types."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


class Counter:
    """Thread-safe counter metric."""

    def __init__(self, name: str, description: str, label_names: Optional[List[str]] = None) -> None:
        self.name = name
        self.description = description
        self.label_names = label_names or []
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = defaultdict(float)
        self._lock = threading.Lock()

    def _normalize_labels(self, labels: Optional[Dict[str, str]]) -> Tuple[Tuple[str, str], ...]:
        if not labels:
            return ()
        return tuple(sorted((k, str(v)) for k, v in labels.items()))

    def inc(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment counter by positive value."""
        if value < 0:
            raise ValueError("Counter increments must be non-negative")
        norm = self._normalize_labels(labels)
        with self._lock:
            self._values[norm] += value

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Get current counter value for labels."""
        norm = self._normalize_labels(labels)
        with self._lock:
            return self._values[norm]

    def reset(self) -> None:
        """Reset all values for this counter."""
        with self._lock:
            self._values.clear()

    def format_prometheus(self) -> List[str]:
        """Format metric into Prometheus text representation lines."""
        lines = [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} {MetricType.COUNTER}",
        ]
        with self._lock:
            if not self._values:
                lines.append(f"{self.name} 0")
            for label_tuple, val in sorted(self._values.items()):
                if label_tuple:
                    label_str = ",".join(f'{k}="{v}"' for k, v in label_tuple)
                    lines.append(f"{self.name}{{{label_str}}} {val}")
                else:
                    lines.append(f"{self.name} {val}")
        return lines


class Gauge:
    """Thread-safe gauge metric that can increase or decrease."""

    def __init__(self, name: str, description: str, label_names: Optional[List[str]] = None) -> None:
        self.name = name
        self.description = description
        self.label_names = label_names or []
        self._values: Dict[Tuple[Tuple[str, str], ...], float] = defaultdict(float)
        self._lock = threading.Lock()

    def _normalize_labels(self, labels: Optional[Dict[str, str]]) -> Tuple[Tuple[str, str], ...]:
        if not labels:
            return ()
        return tuple(sorted((k, str(v)) for k, v in labels.items()))

    def set(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set gauge to exact value."""
        norm = self._normalize_labels(labels)
        with self._lock:
            self._values[norm] = float(value)

    def inc(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment gauge."""
        norm = self._normalize_labels(labels)
        with self._lock:
            self._values[norm] += value

    def dec(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        """Decrement gauge."""
        norm = self._normalize_labels(labels)
        with self._lock:
            self._values[norm] -= value

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        """Get current gauge value."""
        norm = self._normalize_labels(labels)
        with self._lock:
            return self._values[norm]

    def reset(self) -> None:
        """Reset gauge values."""
        with self._lock:
            self._values.clear()

    def format_prometheus(self) -> List[str]:
        """Format metric into Prometheus text representation lines."""
        lines = [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} {MetricType.GAUGE}",
        ]
        with self._lock:
            if not self._values:
                lines.append(f"{self.name} 0")
            for label_tuple, val in sorted(self._values.items()):
                if label_tuple:
                    label_str = ",".join(f'{k}="{v}"' for k, v in label_tuple)
                    lines.append(f"{self.name}{{{label_str}}} {val}")
                else:
                    lines.append(f"{self.name} {val}")
        return lines


class Histogram:
    """Thread-safe histogram metric for recording latency and distributions."""

    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(
        self,
        name: str,
        description: str,
        buckets: Optional[Tuple[float, ...]] = None,
        label_names: Optional[List[str]] = None,
    ) -> None:
        self.name = name
        self.description = description
        self.buckets = tuple(sorted(buckets or self.DEFAULT_BUCKETS))
        self.label_names = label_names or []
        # Map label_tuple -> (bucket_counts, sum, count)
        self._counts: Dict[Tuple[Tuple[str, str], ...], Dict[float, int]] = defaultdict(lambda: defaultdict(int))
        self._sums: Dict[Tuple[Tuple[str, str], ...], float] = defaultdict(float)
        self._totals: Dict[Tuple[Tuple[str, str], ...], int] = defaultdict(int)
        self._lock = threading.Lock()

    def _normalize_labels(self, labels: Optional[Dict[str, str]]) -> Tuple[Tuple[str, str], ...]:
        if not labels:
            return ()
        return tuple(sorted((k, str(v)) for k, v in labels.items()))

    def observe(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record an observation in the histogram."""
        norm = self._normalize_labels(labels)
        with self._lock:
            self._sums[norm] += value
            self._totals[norm] += 1
            for b in self.buckets:
                if value <= b:
                    self._counts[norm][b] += 1

    def reset(self) -> None:
        """Reset all histogram buckets."""
        with self._lock:
            self._counts.clear()
            self._sums.clear()
            self._totals.clear()

    def format_prometheus(self) -> List[str]:
        """Format metric into Prometheus text representation lines."""
        lines = [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} {MetricType.HISTOGRAM}",
        ]
        with self._lock:
            all_labels = set(self._totals.keys())
            if not all_labels:
                all_labels.add(())

            for label_tuple in sorted(all_labels):
                base_labels = dict(label_tuple)
                cumulative = 0
                for b in self.buckets:
                    cumulative += self._counts[label_tuple].get(b, 0)
                    b_str = "+Inf" if b == float("inf") else str(b)
                    merged = dict(base_labels)
                    merged["le"] = b_str
                    label_str = ",".join(f'{k}="{v}"' for k, v in sorted(merged.items()))
                    lines.append(f"{self.name}_bucket{{{label_str}}} {cumulative}")

                # +Inf bucket equals total count
                inf_labels = dict(base_labels)
                inf_labels["le"] = "+Inf"
                inf_label_str = ",".join(f'{k}="{v}"' for k, v in sorted(inf_labels.items()))
                lines.append(f"{self.name}_bucket{{{inf_label_str}}} {self._totals[label_tuple]}")

                # Sum and count
                if base_labels:
                    b_str = ",".join(f'{k}="{v}"' for k, v in sorted(base_labels.items()))
                    lines.append(f"{self.name}_sum{{{b_str}}} {self._sums[label_tuple]}")
                    lines.append(f"{self.name}_count{{{b_str}}} {self._totals[label_tuple]}")
                else:
                    lines.append(f"{self.name}_sum {self._sums[label_tuple]}")
                    lines.append(f"{self.name}_count {self._totals[label_tuple]}")
        return lines


class MetricsRegistry:
    """Central singleton registry holding all telemetry metrics for the service."""

    def __init__(self) -> None:
        self.login_total = Counter(
            "auth_logins_total",
            "Total login attempts by status, tenant and provider",
            ["status", "tenant_id", "provider"],
        )
        self.registration_total = Counter(
            "auth_registrations_total",
            "Total user registrations by status and tenant",
            ["status", "tenant_id"],
        )
        self.token_refresh_total = Counter(
            "auth_token_refreshes_total",
            "Total token refresh requests by status",
            ["status"],
        )
        self.rate_limit_hits = Counter(
            "auth_rate_limit_hits_total",
            "Total requests throttled by rate limit",
            ["endpoint", "tenant_id"],
        )
        self.security_events = Counter(
            "auth_security_events_total",
            "Security events triggered (lockouts, token replay, anomalies)",
            ["event_type", "severity"],
        )
        self.active_sessions = Gauge(
            "auth_active_sessions_gauge",
            "Current count of active sessions",
            ["tenant_id"],
        )
        self.http_requests_total = Counter(
            "http_requests_total",
            "Total HTTP requests received",
            ["method", "endpoint", "status"],
        )
        self.http_request_duration_seconds = Histogram(
            "http_request_duration_seconds",
            "HTTP request latency in seconds",
            (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
            ["method", "endpoint"],
        )
        self._all_metrics = [
            self.login_total,
            self.registration_total,
            self.token_refresh_total,
            self.rate_limit_hits,
            self.security_events,
            self.active_sessions,
            self.http_requests_total,
            self.http_request_duration_seconds,
        ]

    def export_prometheus(self) -> str:
        """Export all registered metrics into a single standard Prometheus format string."""
        output_lines: List[str] = []
        for metric in self._all_metrics:
            output_lines.extend(metric.format_prometheus())
            output_lines.append("")
        return "\n".join(output_lines)

    def reset_all(self) -> None:
        """Reset all metrics (useful for isolated tests)."""
        for metric in self._all_metrics:
            metric.reset()


# Global telemetry singleton
telemetry = MetricsRegistry()

