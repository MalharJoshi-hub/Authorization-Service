"""Unit Tests for Request Body Size & Input Sanitization (Phase 8: Layer 1)."""

from auth_service.core.security.request_validator import sanitize_string, sanitize_dict


def test_sanitize_string():
    dirty = "Hello <script>alert('xss')</script>\x00\x01 World"
    clean = sanitize_string(dirty)
    assert "<script>" not in clean
    assert "&lt;script&gt;" in clean
    assert "\x00" not in clean


def test_sanitize_dict_recursive():
    payload = {
        "name": "Alex <img src=x onerror=alert(1)>",
        "nested": {
            "comment": "<b>bold</b>",
        },
        "tags": ["<i>italic</i>", 123, None],
    }
    sanitized = sanitize_dict(payload)
    assert "&lt;img" in sanitized["name"]
    assert "&lt;b&gt;" in sanitized["nested"]["comment"]
    assert "&lt;i&gt;" in sanitized["tags"][0]
    assert sanitized["tags"][1] == 123
