"""Bounded retries, timeouts and a simple circuit breaker.

Rules (see docs/02-solution-architecture.md, ADR-007):
* Every outbound call has a timeout.
* Only *transient* failures are retried, with exponential backoff + jitter and a
  hard cap on attempts.
* Non-idempotent operations are retried only when they carry an idempotency key.
* A circuit breaker sheds load from a failing dependency and triggers the
  agent's fallback path (human hand-off) instead of hammering the system.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


class TransientError(Exception):
    """Retryable: timeouts, 429, 5xx, connection resets."""


class PermanentError(Exception):
    """Not retryable: validation, 4xx authz, business rule rejection."""


class CircuitOpenError(Exception):
    pass


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 5, reset_after_s: float = 30.0) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_after_s = reset_after_s
        self._failures = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> str:
        if self._opened_at is None:
            return "closed"
        if time.monotonic() - self._opened_at >= self.reset_after_s:
            return "half_open"
        return "open"

    def before_call(self) -> None:
        if self.state == "open":
            raise CircuitOpenError(f"circuit {self.name} is open")

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = time.monotonic()


async def call_with_resilience(
    fn: Callable[[], Awaitable[T]],
    *,
    timeout_s: float,
    max_retries: int,
    breaker: CircuitBreaker | None = None,
    base_delay_s: float = 0.2,
    max_delay_s: float = 2.0,
    retry_on: tuple[type[BaseException], ...] = (TransientError, asyncio.TimeoutError, ConnectionError),
) -> T:
    attempt = 0
    while True:
        if breaker:
            breaker.before_call()
        try:
            result = await asyncio.wait_for(fn(), timeout=timeout_s)
            if breaker:
                breaker.record_success()
            return result
        except retry_on:
            if breaker:
                breaker.record_failure()
            if attempt >= max_retries:
                raise
            delay = min(max_delay_s, base_delay_s * (2**attempt)) * (0.5 + random.random() / 2)  # noqa: S311 - retry jitter, not crypto
            attempt += 1
            await asyncio.sleep(delay)
