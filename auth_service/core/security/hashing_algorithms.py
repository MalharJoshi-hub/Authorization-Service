"""Multi-algorithm cryptographic password hashing module.

Supports modern memory-hard and computationally intensive hash functions:
- Argon2id (OWASP recommended primary)
- Bcrypt (Industry standard)
- PBKDF2-HMAC-SHA256 (FIPS 140-2 compliance)
- SCrypt (Custom memory-hard alternative)

Includes automatic algorithm detection, parameter verification, and transparent
re-hashing upgrade triggers for legacy password hashes upon authentication.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Dict, Optional, Tuple

import bcrypt

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False


class HashAlgorithm:
    """Supported password hash algorithm identifiers."""

    ARGON2ID = "argon2id"
    BCRYPT = "bcrypt"
    PBKDF2_SHA256 = "pbkdf2_sha256"
    SCRYPT = "scrypt"


class MultiAlgorithmHasher:
    """Unified password hashing engine with multi-algorithm support and upgrade detection."""

    DEFAULT_PBKDF2_ITERATIONS = 600_000
    DEFAULT_BCRYPT_ROUNDS = 12
    DEFAULT_SCRYPT_N = 16384
    DEFAULT_SCRYPT_R = 8
    DEFAULT_SCRYPT_P = 1

    def __init__(self, preferred_algorithm: str = HashAlgorithm.BCRYPT) -> None:
        self.preferred_algorithm = preferred_algorithm
        if HAS_ARGON2:
            self._argon2 = PasswordHasher(
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                salt_len=16,
            )
        else:
            self._argon2 = None

    def identify_algorithm(self, hashed_password: str) -> str:
        """Identify which algorithm produced a given hash string."""
        if hashed_password.startswith("$argon2id$") or hashed_password.startswith("$argon2i$"):
            return HashAlgorithm.ARGON2ID
        if hashed_password.startswith("$2a$") or hashed_password.startswith("$2b$") or hashed_password.startswith("$2y$"):
            return HashAlgorithm.BCRYPT
        if hashed_password.startswith("pbkdf2_sha256$"):
            return HashAlgorithm.PBKDF2_SHA256
        if hashed_password.startswith("scrypt$"):
            return HashAlgorithm.SCRYPT
        return "unknown"

    def hash(self, password: str, algorithm: Optional[str] = None) -> str:
        """Hash a plaintext password using the specified or preferred algorithm."""
        algo = algorithm or self.preferred_algorithm

        if algo == HashAlgorithm.ARGON2ID:
            if not self._argon2:
                # Fallback to bcrypt if argon2-cffi is not installed
                return self._hash_bcrypt(password)
            return self._argon2.hash(password)

        elif algo == HashAlgorithm.BCRYPT:
            return self._hash_bcrypt(password)

        elif algo == HashAlgorithm.PBKDF2_SHA256:
            return self._hash_pbkdf2(password)

        elif algo == HashAlgorithm.SCRYPT:
            return self._hash_scrypt(password)

        else:
            raise ValueError(f"Unsupported hashing algorithm: {algo}")

    def verify(self, plain_password: str, hashed_password: str) -> bool:
        """Verify plaintext password against hash using its identified algorithm."""
        algo = self.identify_algorithm(hashed_password)

        if algo == HashAlgorithm.ARGON2ID:
            if not self._argon2:
                return False
            try:
                return self._argon2.verify(hashed_password, plain_password)
            except VerifyMismatchError:
                return False
            except Exception:
                return False

        elif algo == HashAlgorithm.BCRYPT:
            try:
                return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
            except Exception:
                return False

        elif algo == HashAlgorithm.PBKDF2_SHA256:
            return self._verify_pbkdf2(plain_password, hashed_password)

        elif algo == HashAlgorithm.SCRYPT:
            return self._verify_scrypt(plain_password, hashed_password)

        return False

    def needs_rehash(self, hashed_password: str) -> bool:
        """Determine whether hash should be re-hashed to the preferred algorithm or newer parameters."""
        algo = self.identify_algorithm(hashed_password)
        if algo != self.preferred_algorithm:
            return True

        if algo == HashAlgorithm.BCRYPT:
            # Check if bcrypt rounds is less than default
            parts = hashed_password.split("$")
            if len(parts) >= 3:
                try:
                    rounds = int(parts[2])
                    if rounds < self.DEFAULT_BCRYPT_ROUNDS:
                        return True
                except ValueError:
                    return True

        elif algo == HashAlgorithm.PBKDF2_SHA256:
            parts = hashed_password.split("$")
            if len(parts) == 4:
                try:
                    iterations = int(parts[1])
                    if iterations < self.DEFAULT_PBKDF2_ITERATIONS:
                        return True
                except ValueError:
                    return True

        return False

    def _hash_bcrypt(self, password: str) -> str:
        salt = bcrypt.gensalt(rounds=self.DEFAULT_BCRYPT_ROUNDS)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def _hash_pbkdf2(self, password: str, iterations: Optional[int] = None) -> str:
        iters = iterations or self.DEFAULT_PBKDF2_ITERATIONS
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")
        return f"pbkdf2_sha256${iters}${salt_b64}${key_b64}"

    def _verify_pbkdf2(self, password: str, hashed_password: str) -> bool:
        try:
            parts = hashed_password.split("$")
            if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
                return False
            iters = int(parts[1])
            salt = base64.b64decode(parts[2].encode("ascii"))
            expected_key = base64.b64decode(parts[3].encode("ascii"))
            computed_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
            return hmac.compare_digest(computed_key, expected_key)
        except Exception:
            return False

    def _hash_scrypt(self, password: str) -> str:
        salt = secrets.token_bytes(16)
        key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=self.DEFAULT_SCRYPT_N,
            r=self.DEFAULT_SCRYPT_R,
            p=self.DEFAULT_SCRYPT_P,
        )
        salt_b64 = base64.b64encode(salt).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")
        return f"scrypt${self.DEFAULT_SCRYPT_N}${self.DEFAULT_SCRYPT_R}${self.DEFAULT_SCRYPT_P}${salt_b64}${key_b64}"

    def _verify_scrypt(self, password: str, hashed_password: str) -> bool:
        try:
            parts = hashed_password.split("$")
            if len(parts) != 6 or parts[0] != "scrypt":
                return False
            n = int(parts[1])
            r = int(parts[2])
            p = int(parts[3])
            salt = base64.b64decode(parts[4].encode("ascii"))
            expected_key = base64.b64decode(parts[5].encode("ascii"))
            computed_key = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=n,
                r=r,
                p=p,
            )
            return hmac.compare_digest(computed_key, expected_key)
        except Exception:
            return False


# Global singleton
password_hasher = MultiAlgorithmHasher(preferred_algorithm=HashAlgorithm.BCRYPT)
