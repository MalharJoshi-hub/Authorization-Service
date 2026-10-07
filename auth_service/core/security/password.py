"""Password Hashing and Complexity Validation Module (Layer 1: Security Core).

Provides Bcrypt password hashing with configurable salt rounds and enforces
strict enterprise password complexity policies.
"""

import re
import secrets
import bcrypt
from typing import Tuple
from auth_service.config import settings
from auth_service.core.exceptions import ValidationError


def hash_password(plain_password: str, rounds: int = None) -> str:
    """Hash a plaintext password using Bcrypt with salt rounds.

    Args:
        plain_password: The plaintext string password.
        rounds: Optional cost factor rounds (defaults to settings.PASSWORD_BCRYPT_ROUNDS, typically 12).

    Returns:
        The utf-8 encoded Bcrypt hash string.
    """
    if not plain_password:
        raise ValidationError("Password cannot be empty")

    cost = rounds or settings.PASSWORD_BCRYPT_ROUNDS
    # Bcrypt truncates at 72 bytes; OWASP recommends pre-hashing with SHA-256 for passwords > 72 bytes
    password_bytes = plain_password.encode("utf-8")
    if len(password_bytes) > 72:
        import hashlib
        password_bytes = hashlib.sha256(password_bytes).digest()
    salt = bcrypt.gensalt(rounds=cost)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored Bcrypt hash using constant-time evaluation.

    Args:
        plain_password: The candidate plaintext password.
        hashed_password: The previously computed Bcrypt hash.

    Returns:
        True if the password matches, False otherwise.
    """
    if not plain_password or not hashed_password:
        return False

    try:
        password_bytes = plain_password.encode("utf-8")
        if len(password_bytes) > 72:
            import hashlib
            password_bytes = hashlib.sha256(password_bytes).digest()
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except (ValueError, TypeError):
        return False


def validate_password_complexity(password: str) -> Tuple[bool, str]:
    """Validate password against enterprise complexity standards.

    Criteria:
      - Minimum length of 8 characters
      - At least one uppercase English letter (A-Z)
      - At least one lowercase English letter (a-z)
      - At least one numerical digit (0-9)
      - At least one special symbol (!@#$%^&*()_+-=[]{}|;:,.<>?)

    Args:
        password: The candidate password string.

    Returns:
        A tuple of (is_valid: bool, error_message: str).
    """
    if not settings.ENFORCE_PASSWORD_COMPLEXITY:
        if len(password) < 6:
            return False, "Password must be at least 6 characters long."
        return True, ""

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one numerical digit."

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+[\]\\/`~;']", password):
        return False, "Password must contain at least one special character."

    return True, ""


def generate_secure_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password meeting all complexity criteria."""
    length = max(length, 12)
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    lower = "abcdefghijkmnopqrstuvwxyz"
    digits = "23456789"
    special = "!@#$%^&*()_+-="

    # Guarantee at least one character from each required class
    chars = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special),
    ]

    alphabet = upper + lower + digits + special
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
