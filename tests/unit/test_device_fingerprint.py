"""Unit tests for device fingerprinting and telemetry extraction."""

import pytest
from auth_service.core.security.device_fingerprint import DeviceFingerprintService, device_fingerprint_service


def test_extract_device_info_desktop():
    service = DeviceFingerprintService()
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    browser, os_name, device_type, is_bot = service.extract_device_info(ua)

    assert browser == "Chrome"
    assert os_name == "Windows"
    assert device_type == "Desktop"
    assert is_bot is False


def test_extract_device_info_mobile_iphone():
    service = DeviceFingerprintService()
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    browser, os_name, device_type, is_bot = service.extract_device_info(ua)

    assert browser == "Safari"
    assert os_name == "iOS"
    assert device_type == "Mobile"
    assert is_bot is False


def test_extract_device_info_bot():
    service = DeviceFingerprintService()
    ua = "curl/7.88.1"
    browser, os_name, device_type, is_bot = service.extract_device_info(ua)

    assert is_bot is True
    assert device_type == "Server/Script"


def test_compute_fingerprint_deterministic():
    service = DeviceFingerprintService()
    fp1 = service.compute_fingerprint(
        user_agent="Mozilla/5.0 Chrome/120",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        ip_network_prefix="192.168.1.0/24",
    )
    fp2 = service.compute_fingerprint(
        user_agent="Mozilla/5.0 Chrome/120",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        ip_network_prefix="192.168.1.0/24",
    )

    assert fp1.fingerprint_hash == fp2.fingerprint_hash
    assert len(fp1.fingerprint_hash) == 64
    summary = fp1.to_dict()
    assert summary["browser"] == "Chrome"


def test_calculate_risk_delta_known_device():
    service = DeviceFingerprintService()
    fp = service.compute_fingerprint(user_agent="Mozilla/5.0 Chrome/120")
    known_fps = [fp.fingerprint_hash]
    known_os = [fp.os]

    risk, reasons = service.calculate_risk_delta(fp, known_fps, known_os)
    assert risk == 0


def test_calculate_risk_delta_new_device():
    service = DeviceFingerprintService()
    fp = service.compute_fingerprint(user_agent="Mozilla/5.0 Firefox/120 (Android 14; Mobile)")
    known_fps = ["existing_hash_1", "existing_hash_2"]
    known_os = ["Windows"]

    risk, reasons = service.calculate_risk_delta(fp, known_fps, known_os)
    assert risk > 0
    assert any("New/unrecognized device" in r for r in reasons)
    assert any("Unrecognized operating system" in r for r in reasons)


def test_calculate_risk_delta_first_device():
    service = DeviceFingerprintService()
    fp = service.compute_fingerprint(user_agent="Mozilla/5.0 Chrome/120")
    risk, reasons = service.calculate_risk_delta(fp, [], [])
    assert risk == 0
    assert any("Initial device" in r for r in reasons)
