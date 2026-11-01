"""Per-principal token-bucket rate limiting.

This in-process limiter protects a single worker. In production the primary
limit lives at the edge (Azure API Management ``rate-limit-by-key`` /
Front Door WAF); a Redis-backed limiter would be used for cross-worker limits.
"""

from __future__ import annotations

import threading
import time


class TokenBucketLimiter:
    def __init__(self, per_minute: int, burst: int | None = None) -> None:
        self.rate = per_minute / 60.0
        self.capacity = float(burst or max(1, per_minute // 4 or 1))
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            return True
