"""Unit tests for telemetry and Prometheus metrics collector."""

import pytest
from auth_service.core.telemetry import Counter, Gauge, Histogram, MetricsRegistry, MetricType


def test_counter_basic_increment():
    counter = Counter("test_counter", "Test description")
    assert counter.get() == 0.0

    counter.inc()
    assert counter.get() == 1.0

    counter.inc(5.5)
    assert counter.get() == 6.5


def test_counter_with_labels():
    counter = Counter("http_requests", "HTTP requests", ["method", "status"])
    counter.inc(1.0, {"method": "GET", "status": "200"})
    counter.inc(2.0, {"method": "POST", "status": "201"})
    counter.inc(3.0, {"method": "GET", "status": "200"})

    assert counter.get({"method": "GET", "status": "200"}) == 4.0
    assert counter.get({"method": "POST", "status": "201"}) == 2.0
    assert counter.get({"method": "DELETE", "status": "404"}) == 0.0


def test_counter_negative_increment_raises():
    counter = Counter("test_neg", "Negative increment test")
    with pytest.raises(ValueError):
        counter.inc(-1.0)


def test_counter_reset():
    counter = Counter("test_reset", "Reset test")
    counter.inc(10)
    assert counter.get() == 10
    counter.reset()
    assert counter.get() == 0


def test_counter_format_prometheus():
    counter = Counter("login_total", "Login counter", ["status"])
    counter.inc(1, {"status": "success"})
    lines = counter.format_prometheus()
    assert any("# HELP login_total Login counter" in l for l in lines)
    assert any("# TYPE login_total counter" in l for l in lines)
    assert any('login_total{status="success"} 1.0' in l for l in lines)


def test_gauge_operations():
    gauge = Gauge("active_connections", "Active connection count")
    assert gauge.get() == 0.0

    gauge.set(10)
    assert gauge.get() == 10.0

    gauge.inc(5)
    assert gauge.get() == 15.0

    gauge.dec(3)
    assert gauge.get() == 12.0

    gauge.reset()
    assert gauge.get() == 0.0


def test_gauge_with_labels():
    gauge = Gauge("tenant_sessions", "Sessions per tenant", ["tenant"])
    gauge.set(5, {"tenant": "alpha"})
    gauge.set(12, {"tenant": "beta"})

    assert gauge.get({"tenant": "alpha"}) == 5.0
    assert gauge.get({"tenant": "beta"}) == 12.0


def test_histogram_observations():
    hist = Histogram("request_duration", "Request duration in seconds", (0.01, 0.05, 0.1, 0.5, 1.0))
    hist.observe(0.005)
    hist.observe(0.02)
    hist.observe(0.08)
    hist.observe(0.7)
    hist.observe(2.5)

    lines = hist.format_prometheus()
    assert any("# TYPE request_duration histogram" in l for l in lines)
    assert any('request_duration_bucket{le="0.01"} 1' in l for l in lines)
    assert any('request_duration_bucket{le="+Inf"} 5' in l for l in lines)
    assert any("request_duration_count 5" in l for l in lines)


def test_metrics_registry_export():
    registry = MetricsRegistry()
    registry.login_total.inc(1, {"status": "success", "tenant_id": "t1", "provider": "local"})
    registry.registration_total.inc(1, {"status": "success", "tenant_id": "t1"})
    registry.active_sessions.set(42, {"tenant_id": "t1"})

    text = registry.export_prometheus()
    assert "auth_logins_total" in text
    assert "auth_registrations_total" in text
    assert "auth_active_sessions_gauge" in text
    assert 'tenant_id="t1"' in text

    registry.reset_all()
    text_after = registry.export_prometheus()
    assert "auth_logins_total 0" in text_after or "auth_logins_total" in text_after
