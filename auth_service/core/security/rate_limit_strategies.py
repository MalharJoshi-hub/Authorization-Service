"""Throttling & Traffic Shaping Algorithmic Strategies (Layer 1).

Implements token bucket, leaky bucket, and fixed-window algorithms
for high-throughput API gateway traffic control.
"""

import time
from typing import Dict, Tuple


class TokenBucketLimiter:
    """Token Bucket rate limiter supporting burst allowances."""

    def __init__(self, capacity: int, refill_rate_per_sec: float):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill_rate = float(refill_rate_per_sec)
        self.last_update = time.time()

    def allow_request(self, tokens_needed: float = 1.0) -> bool:
        """Evaluate if enough tokens are available."""
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now

        # Add newly generated tokens up to capacity
        self.tokens = min(self.capacity, self.tokens + (elapsed * self.refill_rate))

        if self.tokens >= tokens_needed:
            self.tokens -= tokens_needed
            return True
        return False


class LeakyBucketLimiter:
    """Leaky Bucket rate limiter enforcing smooth constant egress."""

    def __init__(self, capacity: int, leak_rate_per_sec: float):
        self.capacity = float(capacity)
        self.water = 0.0
        self.leak_rate = float(leak_rate_per_sec)
        self.last_leak = time.time()

    def add_request(self) -> bool:
        """Attempt to enqueue request into bucket."""
        now = time.time()
        elapsed = now - self.last_leak
        self.last_leak = now

        # Leak water based on time passed
        self.water = max(0.0, self.water - (elapsed * self.leak_rate))

        if self.water + 1.0 <= self.capacity:
            self.water += 1.0
            return True
        return False


class FixedWindowLimiter:
    """Fixed-Window counter rate limiter."""

    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.counters: Dict[str, Tuple[int, int]] = {}  # key -> (current_window_idx, count)

    def allow(self, key: str) -> bool:
        now = int(time.time())
        window_idx = now // self.window_seconds

        current_idx, count = self.counters.get(key, (window_idx, 0))
        if current_idx != window_idx:
            # New window started
            self.counters[key] = (window_idx, 1)
            return True

        if count < self.limit:
            self.counters[key] = (window_idx, count + 1)
            return True

        return False

