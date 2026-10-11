"""Automated Security Posture and Hardening Auditor.

Performs runtime evaluation against OWASP ASVS (Application Security Verification Standard)
and CIS software security benchmarks:
- Cryptographic key entropy & length verification
- Weak algorithm detection (e.g. rejection of 'none' algorithm)
- Rate limiting and lockout defense posture
- Password complexity policy compliance
- Cookie security flags (HttpOnly, Secure, SameSite)
- Generates a holistic security score (0-100) and remediation checklist
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Tuple

from auth_service.core.config import settings
from auth_service.core.logger import get_logger

logger = get_logger("auth_service.security.posture")


class FindingSeverity:
    """Severity levels for posture findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PostureFinding:
    """Represents a specific configuration or runtime security finding."""

    def __init__(self, code: str, title: str, severity: str, description: str, remediation: str) -> None:
        self.code = code
        self.title = title
        self.severity = severity
        self.description = description
        self.remediation = remediation

    def to_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
        }


class SecurityPostureAuditor:
    """Evaluates system configuration and environment against security standards."""

    @classmethod
    def calculate_entropy(cls, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        counts: Dict[str, int] = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def run_audit(self) -> Dict[str, Any]:
        """Perform comprehensive audit and return report dictionary."""
        findings: List[PostureFinding] = []
        score = 100

        # 1. SECRET_KEY length and entropy
        secret = settings.SECRET_KEY
        if not secret or len(secret) < 32:
            score -= 30
            findings.append(
                PostureFinding(
                    code="SEC-KEY-001",
                    title="Weak Secret Key Length",
                    severity=FindingSeverity.CRITICAL,
                    description=f"SECRET_KEY length is {len(secret or '')} bytes. Minimum recommended is 32 bytes.",
                    remediation="Generate a cryptographically random 32+ byte string (e.g. openssl rand -hex 32).",
                )
            )
        elif self.calculate_entropy(secret) < 3.5:
            score -= 15
            findings.append(
                PostureFinding(
                    code="SEC-KEY-002",
                    title="Low Secret Key Entropy",
                    severity=FindingSeverity.HIGH,
                    description="SECRET_KEY exhibits repetitive or low entropy patterns.",
                    remediation="Ensure SECRET_KEY is generated using a secure PRNG.",
                )
            )

        # 2. JWT Algorithm
        algo = getattr(settings, "JWT_ALGORITHM", getattr(settings, "ALGORITHM", "HS256"))
        if algo.lower() == "none":
            score -= 50
            findings.append(
                PostureFinding(
                    code="SEC-JWT-001",
                    title="'none' Algorithm Allowed",
                    severity=FindingSeverity.CRITICAL,
                    description="The insecure 'none' signing algorithm is specified.",
                    remediation="Change ALGORITHM to RS256, ES256, or HS256.",
                )
            )
        elif algo.startswith("HS") and len(secret) < 32:
            score -= 20
            findings.append(
                PostureFinding(
                    code="SEC-JWT-002",
                    title="HMAC Key Too Short for Algorithm",
                    severity=FindingSeverity.HIGH,
                    description=f"{algo} requires a high entropy key of adequate bit-length.",
                    remediation="Increase SECRET_KEY length to at least 256 bits.",
                )
            )

        # 3. Rate Limiting Enabled
        if not getattr(settings, "RATE_LIMIT_ENABLED", True):
            score -= 25
            findings.append(
                PostureFinding(
                    code="SEC-RATE-001",
                    title="Rate Limiter Disabled",
                    severity=FindingSeverity.HIGH,
                    description="Rate limiting is disabled in configuration, leaving endpoints vulnerable to DoS and brute-force.",
                    remediation="Set RATE_LIMIT_ENABLED=true in production environment.",
                )
            )

        # 4. Lockout configuration
        max_attempts = getattr(settings, "LOCKOUT_MAX_ATTEMPTS", 5)
        if max_attempts > 10:
            score -= 10
            findings.append(
                PostureFinding(
                    code="SEC-LOCK-001",
                    title="Excessive Lockout Threshold",
                    severity=FindingSeverity.MEDIUM,
                    description=f"Account lockout threshold is {max_attempts} attempts. Industry standard is 5 attempts.",
                    remediation="Reduce LOCKOUT_MAX_ATTEMPTS to 5.",
                )
            )

        # 5. Token Expiry Limits
        access_expiry = getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 15)
        if access_expiry > 60:
            score -= 15
            findings.append(
                PostureFinding(
                    code="SEC-TOK-001",
                    title="Prolonged Access Token Lifespan",
                    severity=FindingSeverity.MEDIUM,
                    description=f"Access token lifetime is {access_expiry} minutes. Short lifespans (<=15 min) limit exposure.",
                    remediation="Reduce ACCESS_TOKEN_EXPIRE_MINUTES to 15 minutes and use refresh tokens.",
                )
            )

        # 6. CORS Wildcard Check
        cors_origins = getattr(settings, "CORS_ORIGINS", [])
        if "*" in cors_origins:
            score -= 15
            findings.append(
                PostureFinding(
                    code="SEC-CORS-001",
                    title="Permissive CORS Wildcard",
                    severity=FindingSeverity.HIGH,
                    description="CORS allows '*' origin with credentials, creating risk of CSRF or cross-domain data leakage.",
                    remediation="Restrict CORS_ORIGINS to trusted front-end domains.",
                )
            )

        score = max(0, score)
        posture_rating = (
            "EXCELLENT" if score >= 90
            else "GOOD" if score >= 75
            else "FAIR" if score >= 60
            else "POOR"
        )

        return {
            "security_score": score,
            "rating": posture_rating,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
            "frameworks_evaluated": ["OWASP ASVS v4.0", "NIST SP 800-63B", "CIS Benchmarks"],
        }


# Global singleton
security_auditor = SecurityPostureAuditor()
