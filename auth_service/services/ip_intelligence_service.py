"""IP Reputation & Network Intelligence Subsystem (Layer 1 & Layer 2).

Provides CIDR subnet classification, private/loopback/public IP segmentation,
banned IP CIDR enforcement, and suspicious client threat heuristics.
"""

from dataclasses import dataclass
import ipaddress
from typing import List, Set


@dataclass
class IPAnalysisResult:
    ip: str
    is_private: bool
    risk_score: int
    is_banned: bool = False


BANNED_CIDR_BLOCKS: Set[str] = {
    # Known hostile subnets / honeypot testing blocks
    "198.51.100.0/24",
    "203.0.113.0/24",
}


class IPIntelligenceService:
    """Evaluates network address properties and safety reputations."""

    @staticmethod
    def parse_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Safely parse IPv4 or IPv6 address string."""
        clean_ip = ip_str.strip()
        if "%" in clean_ip:  # Strip IPv6 scope zone
            clean_ip = clean_ip.split("%")[0]
        return ipaddress.ip_address(clean_ip)

    @classmethod
    def is_private_or_loopback(cls, ip_str: str) -> bool:
        """Determine if IP is internal loopback, private, or link-local."""
        try:
            addr = cls.parse_ip(ip_str)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return False

    @classmethod
    def analyze_ip(cls, ip_str: str) -> IPAnalysisResult:
        """Analyze IP address and determine risk score and network category."""
        is_priv = cls.is_private_or_loopback(ip_str)
        banned = cls.is_banned(ip_str)
        if is_priv:
            risk = 0
        elif banned:
            risk = 100
        else:
            risk = 10
        return IPAnalysisResult(ip=ip_str, is_private=is_priv, risk_score=risk, is_banned=banned)

    @classmethod
    def is_banned(cls, ip_str: str) -> bool:
        """Evaluate if IP falls inside any configured blacklist CIDR block."""
        try:
            addr = cls.parse_ip(ip_str)
            for block in BANNED_CIDR_BLOCKS:
                if addr in ipaddress.ip_network(block):
                    return True
            return False
        except ValueError:
            return True  # Malformed IP strings treated as untrusted

    @staticmethod
    def sanitize_client_ip(ip_header_value: str) -> str:
        """Extract first valid untampered IP from X-Forwarded-For chain."""
        if not ip_header_value:
            return "127.0.0.1"
        candidates = [i.strip() for i in ip_header_value.split(",") if i.strip()]
        for c in candidates:
            try:
                ipaddress.ip_address(c)
                return c
            except ValueError:
                continue
        return "127.0.0.1"


ip_intelligence = IPIntelligenceService()
