"""Enterprise Password Governance & Policy Enforcement Service (Layer 1).

Evaluates password entropy, detects compromised passwords from common dictionary lists,
and enforces historical password rotation rules.
"""

import math
from typing import List, Tuple
from auth_service.core.security.password import verify_password


# Top common compromised passwords to block immediately
COMMON_BREACHED_PASSWORDS = {
    "password", "password123", "12345678", "qwertyuiop", "admin1234",
    "welcome1", "letmein123", "monkey123", "dragon123", "football1",
    "master123", "sunshine1", "iloveyou1", "trustno1", "superman1"
}


class PasswordPolicyService:
    """Enforces enterprise password strength and lifecycle policies."""

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate Shannon entropy bits for a candidate password."""
        if not password:
            return 0.0

        charset_size = 0
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32

        if charset_size == 0:
            return 0.0

        # Entropy = length * log2(pool_size)
        return len(password) * math.log2(charset_size)

    @classmethod
    def check_breached_dictionary(cls, password: str) -> bool:
        """Return True if password matches known common compromised passwords."""
        return password.lower().strip() in COMMON_BREACHED_PASSWORDS

    @classmethod
    def check_password_history(
        cls, candidate_password: str, historical_hashes: List[str]
    ) -> bool:
        """Verify candidate password does not match any recent historical hashes.

        Returns:
            True if candidate password was previously used (violation), False if safe.
        """
        for h in historical_hashes:
            if verify_password(candidate_password, h):
                return True
        return False

    @classmethod
    def evaluate_comprehensive(
        cls,
        candidate_password: str,
        historical_hashes: List[str] = None,
        min_entropy_bits: float = 40.0,
    ) -> Tuple[bool, str]:
        """Run full evaluation suite on a candidate password."""
        if cls.check_breached_dictionary(candidate_password):
            return False, "This password is too common and has appeared in public breaches. Choose a more unique phrase."

        entropy = cls.calculate_entropy(candidate_password)
        if entropy < min_entropy_bits:
            return False, f"Password complexity is insufficient (Entropy: {entropy:.1f} bits, Required: {min_entropy_bits} bits)."

        if historical_hashes and cls.check_password_history(candidate_password, historical_hashes):
            return False, "You cannot reuse any of your previous 5 passwords."

        return True, ""

    @classmethod
    def evaluate_strength(cls, password: str) -> Tuple[int, List[str]]:
        """Evaluate password strength returning score (0-100) and list of improvement reasons."""
        score = 0
        reasons = []
        if not password:
            return 0, ["Password cannot be empty"]

        length = len(password)
        if length >= 20:
            score += 35
        elif length >= 14:
            score += 25
        elif length >= 8:
            score += 15
        else:
            reasons.append("Password is too short (min 8 characters)")

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        if has_lower:
            score += 15
        else:
            reasons.append("Missing lowercase character")

        if has_upper:
            score += 15
        else:
            reasons.append("Missing uppercase character")

        if has_digit:
            score += 15
        else:
            reasons.append("Missing digit")

        if has_special:
            score += 15
        else:
            reasons.append("Missing special character")

        if cls.check_breached_dictionary(password):
            score = min(score, 20)
            reasons.append("Password appears in known breaches")

        score = max(0, min(100, score))
        return score, reasons


password_policy_service = PasswordPolicyService()
