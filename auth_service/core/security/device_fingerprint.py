"""Device fingerprinting and risk assessment engine.

Calculates stable hardware/browser signatures from HTTP headers, client hints, and network
characteristics. Detects novel devices, suspicious user-agent anomalies, and risk score adjustments.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple


class DeviceFingerprint:
    """Represents a computed device fingerprint and parsed telemetry attributes."""

    def __init__(
        self,
        fingerprint_hash: str,
        browser: str,
        os: str,
        device_type: str,
        is_bot: bool,
        raw_attributes: Dict[str, Any],
    ) -> None:
        self.fingerprint_hash = fingerprint_hash
        self.browser = browser
        self.os = os
        self.device_type = device_type
        self.is_bot = is_bot
        self.raw_attributes = raw_attributes

    def to_dict(self) -> Dict[str, Any]:
        """Convert fingerprint summary to dictionary."""
        return {
            "fingerprint_hash": self.fingerprint_hash,
            "browser": self.browser,
            "os": self.os,
            "device_type": self.device_type,
            "is_bot": self.is_bot,
            "attributes": self.raw_attributes,
        }


class DeviceFingerprintService:
    """Service to parse headers and generate deterministic device fingerprints."""

    BOT_USER_AGENTS = (
        "curl",
        "postman",
        "python-requests",
        "httpx",
        "aiohttp",
        "scrapy",
        "wget",
        "headlesschrome",
        "phantomjs",
        "selenium",
    )

    def extract_device_info(self, user_agent: str) -> Tuple[str, str, str, bool]:
        """Parse browser, operating system, and device type from User-Agent string."""
        ua = (user_agent or "").lower()
        is_bot = any(bot in ua for bot in self.BOT_USER_AGENTS)

        # OS detection
        os_name = "Unknown"
        if "iphone" in ua or "ipad" in ua or "ios" in ua:
            os_name = "iOS"
        elif "windows" in ua:
            os_name = "Windows"
        elif "mac os" in ua or "macintosh" in ua:
            os_name = "macOS"
        elif "android" in ua:
            os_name = "Android"
        elif "linux" in ua:
            os_name = "Linux"

        # Browser detection
        browser_name = "Unknown"
        if "edg/" in ua or "edge/" in ua:
            browser_name = "Edge"
        elif "chrome/" in ua:
            browser_name = "Chrome"
        elif "firefox/" in ua:
            browser_name = "Firefox"
        elif "safari/" in ua:
            browser_name = "Safari"
        elif "opera/" in ua or "opr/" in ua:
            browser_name = "Opera"
        elif is_bot:
            browser_name = "Automated/Bot"

        # Device type
        device_type = "Desktop"
        if "mobile" in ua or "android" in ua or "iphone" in ua:
            device_type = "Mobile"
        elif "ipad" in ua or "tablet" in ua:
            device_type = "Tablet"
        elif is_bot:
            device_type = "Server/Script"

        return browser_name, os_name, device_type, is_bot

    def compute_fingerprint(
        self,
        user_agent: Optional[str] = None,
        accept_language: Optional[str] = None,
        accept_encoding: Optional[str] = None,
        sec_ch_ua: Optional[str] = None,
        sec_ch_ua_platform: Optional[str] = None,
        ip_network_prefix: Optional[str] = None,
        custom_entropy: Optional[str] = None,
    ) -> DeviceFingerprint:
        """Generate a SHA-256 fingerprint hash from combination of client signals."""
        ua_clean = (user_agent or "unknown").strip()
        lang_clean = (accept_language or "unknown").strip().lower()
        enc_clean = (accept_encoding or "unknown").strip().lower()
        ch_ua = (sec_ch_ua or "").strip()
        ch_platform = (sec_ch_ua_platform or "").strip()
        prefix = (ip_network_prefix or "").strip()

        browser, os_name, device_type, is_bot = self.extract_device_info(ua_clean)

        raw_attributes = {
            "user_agent": ua_clean,
            "accept_language": lang_clean,
            "accept_encoding": enc_clean,
            "sec_ch_ua": ch_ua,
            "sec_ch_ua_platform": ch_platform,
            "ip_network_prefix": prefix,
            "custom_entropy": custom_entropy or "",
        }

        # Deterministic serialization for hashing
        serialized = json.dumps(raw_attributes, sort_keys=True)
        fingerprint_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        return DeviceFingerprint(
            fingerprint_hash=fingerprint_hash,
            browser=browser,
            os=os_name,
            device_type=device_type,
            is_bot=is_bot,
            raw_attributes=raw_attributes,
        )

    def calculate_risk_delta(
        self,
        current_fp: DeviceFingerprint,
        known_fingerprints: List[str],
        known_os_list: List[str],
    ) -> Tuple[int, List[str]]:
        """Calculate incremental risk points (0-100) and warning reasons for a login event."""
        risk_score = 0
        reasons: List[str] = []

        if current_fp.is_bot:
            risk_score += 40
            reasons.append("Automated client User-Agent detected")

        if not known_fingerprints:
            # First ever device for this user
            reasons.append("Initial device registration")
            return 0, reasons

        if current_fp.fingerprint_hash not in known_fingerprints:
            risk_score += 25
            reasons.append("New/unrecognized device fingerprint")

            # Check if OS also changed
            if known_os_list and current_fp.os not in known_os_list:
                risk_score += 20
                reasons.append(f"Unrecognized operating system ({current_fp.os})")

        return min(risk_score, 100), reasons


# Global singleton
device_fingerprint_service = DeviceFingerprintService()
