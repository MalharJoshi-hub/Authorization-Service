"""Compromised and breached password checking system.

Implements NIST SP 800-63B guidelines prohibiting known breached passwords.
Features:
- Offline local high-frequency dictionary matching
- HaveIBeenPwned k-Anonymity API integration (sends only 5-char SHA-1 prefix)
- In-memory cache for recent hash lookups to reduce network overhead
- Graceful offline fallback on network or DNS failure
"""

from __future__ import annotations

import hashlib
import time
from typing import Dict, Optional, Set, Tuple

import httpx

from auth_service.core.logger import get_logger

logger = get_logger("auth_service.security.pwned_passwords")


class BreachedPasswordError(ValueError):
    """Raised when a supplied password appears in known breach datasets."""

    def __init__(self, count: int) -> None:
        self.breach_count = count
        super().__init__(
            f"This password has appeared in {count:,} known data breaches and cannot be used. "
            "Please choose a unique, stronger password."
        )


class PwnedPasswordChecker:
    """Validator that checks passwords against known breaches."""

    API_URL = "https://api.pwnedpasswords.com/range/"

    # Top common passwords blocked instantly offline without network call
    COMMON_PASSWORDS: Set[str] = {
        "password", "password123", "123456", "12345678", "123456789",
        "qwerty", "12345", "1234", "dragon", "pussy", "baseball",
        "football", "letmein", "monkey", "shadow", "master", "666666",
        "superman", "killer", "trustno1", "admin", "admin123", "welcome",
        "welcome1", "iloveyou", "princess", "sunshine", "starwars",
        "solo", "passw0rd", "secret", "changeit", "administrator",
        "pass1234", "test1234", "qwertyuiop", "testing", "default",
    }

    def __init__(
        self,
        api_timeout: float = 2.0,
        cache_ttl_seconds: int = 3600,
        enable_remote_check: bool = True,
    ) -> None:
        self.api_timeout = api_timeout
        self.cache_ttl_seconds = cache_ttl_seconds
        self.enable_remote_check = enable_remote_check
        # Map: sha1_prefix -> (timestamp, {suffix: count})
        self._cache: Dict[str, Tuple[float, Dict[str, int]]] = {}

    def is_common_offline(self, password: str) -> bool:
        """Check if password matches common weak dictionary entries."""
        return password.lower() in self.COMMON_PASSWORDS

    async def check_password(self, password: str) -> int:
        """Check if password is breached.

        Returns 0 if safe, or the breach count if found.
        Raises BreachedPasswordError if count > 0.
        """
        if self.is_common_offline(password):
            logger.warning("Password rejected via local dictionary match")
            raise BreachedPasswordError(count=1000000)

        if not self.enable_remote_check:
            return 0

        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Check in-memory cache
        now = time.time()
        cached = self._cache.get(prefix)
        if cached and (now - cached[0]) < self.cache_ttl_seconds:
            counts_map = cached[1]
            breach_count = counts_map.get(suffix, 0)
            if breach_count > 0:
                raise BreachedPasswordError(count=breach_count)
            return 0

        # Query HaveIBeenPwned k-Anonymity API
        counts_map = await self._fetch_range(prefix)
        if counts_map is not None:
            self._cache[prefix] = (now, counts_map)
            breach_count = counts_map.get(suffix, 0)
            if breach_count > 0:
                logger.warning("Password detected in HaveIBeenPwned breach dataset: count=%s", breach_count)
                raise BreachedPasswordError(count=breach_count)

        return 0

    async def _fetch_range(self, prefix: str) -> Optional[Dict[str, int]]:
        """Fetch hash suffixes from HaveIBeenPwned range API."""
        url = f"{self.API_URL}{prefix}"
        try:
            async with httpx.AsyncClient(timeout=self.api_timeout) as client:
                resp = await client.get(url, headers={"User-Agent": "Auth-Service-Pwned-Check"})
                if resp.status_code != 200:
                    logger.warning("HIBP API returned status %s for prefix %s", resp.status_code, prefix)
                    return None

                result: Dict[str, int] = {}
                for line in resp.text.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        suf = parts[0].strip().upper()
                        try:
                            c = int(parts[1].strip())
                            result[suf] = c
                        except ValueError:
                            continue
                return result
        except Exception as exc:
            # Graceful degradation on network timeout or DNS failure
            logger.debug("HIBP API lookup failed gracefully: %s", exc)
            return None


# Global singleton
pwned_checker = PwnedPasswordChecker()
