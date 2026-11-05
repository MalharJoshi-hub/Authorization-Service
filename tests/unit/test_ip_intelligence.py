"""Unit Tests for Network IP Intelligence & CIDR Evaluation (Phase 8)."""

from auth_service.services.ip_intelligence_service import ip_intelligence


def test_is_private_or_loopback():
    assert ip_intelligence.is_private_or_loopback("127.0.0.1") is True
    assert ip_intelligence.is_private_or_loopback("::1") is True
    assert ip_intelligence.is_private_or_loopback("192.168.1.50") is True
    assert ip_intelligence.is_private_or_loopback("10.0.0.1") is True
    assert ip_intelligence.is_private_or_loopback("8.8.8.8") is False
    assert ip_intelligence.is_private_or_loopback("1.1.1.1") is False


def test_is_banned_cidr():
    assert ip_intelligence.is_banned("198.51.100.25") is True
    assert ip_intelligence.is_banned("203.0.113.10") is True
    assert ip_intelligence.is_banned("8.8.8.8") is False


def test_sanitize_client_ip():
    assert ip_intelligence.sanitize_client_ip("203.0.113.195, 10.0.0.1") == "203.0.113.195"
    assert ip_intelligence.sanitize_client_ip("invalid_ip, 1.1.1.1") == "1.1.1.1"
    assert ip_intelligence.sanitize_client_ip("") == "127.0.0.1"

