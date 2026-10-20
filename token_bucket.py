"""Token-bucket rate limiter.

Faithful, cleaned-up Python port of the reference JavaScript TokenBucket
(capacity / refillAmount / refillTime, one token per request, reject when
empty), with the rough edges of the original fixed:

  * Refill is *discrete*: ``refill_amount`` tokens are added every
    ``refill_time`` seconds (the JS model). The reference implementation
    reset the timestamp to "now" on every refill, which threw away the
    remainder of a cycle and made the effective rate drift below the
    configured one. Here the timestamp advances by whole cycles only, so the
    long-run rate is exactly ``refill_amount / refill_time``.
  * No dead code: the reference had an unreachable "bucket not found" branch
    and a ``chalk.red(...)`` call that was never printed.
  * ``chalk`` is replaced by the standard library ``logging`` module
    (colored output included, but optional and side-effect free).
  * Idle buckets are pruned, so the store cannot grow without bound.
  * A cooldown penalty is kept: while a client is rejected, refill is
    suspended and further hammering extends the lock exponentially
    (capped at ``max_cooldown``), so "instant refresh" recovery is gone.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger("rate_limit")

# Optional ANSI colouring for the log lines (no external dependency).
_COLORS = {
    "accepted": "\033[32m",
    "rejected": "\033[31m",
    "reset": "\033[0m",
}


def _colorize(text: str, kind: str) -> str:
    """Wrap *text* in ANSI colour when the output stream supports it."""
    if not os.environ.get("FORCE_COLOR") and not os.isatty(2):
        return text
    return f"{_COLORS[kind]}{text}{_COLORS['reset']}"


@dataclass
class BucketState:
    """Mutable state of one bucket (the JS `{ tokens, ts }` pair)."""

    tokens: float
    ts: float
    last_seen: float = field(default_factory=time.monotonic)

    @property
    def idle_seconds(self) -> float:
        return time.monotonic() - self.last_seen


class TokenBucket:
    """A single bucket: ``capacity`` tokens, refilled every ``refill_time``."""

    def __init__(
        self,
        capacity: int = 5,
        refill_amount: int = 5,
        refill_time: float = 30.0,
        base_cooldown: float = 2.0,
        max_cooldown: float = 30.0,
    ) -> None:
        """
        capacity      : maximum tokens the bucket holds (burst size)
        refill_amount : tokens added every refill cycle
        refill_time   : seconds between refill cycles
        base_cooldown : seconds of suspended refill after a rejection
        max_cooldown  : cap for the exponential backoff while hammering
        """
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_amount <= 0:
            raise ValueError("refill_amount must be positive")
        if refill_time <= 0:
            raise ValueError("refill_time must be positive")

        self.capacity = capacity
        self.refill_amount = refill_amount
        self.refill_time = refill_time
        self.base_cooldown = base_cooldown
        self.max_cooldown = max_cooldown

        self.state = BucketState(tokens=float(capacity), ts=time.monotonic())
        self.locked_until = 0.0   # refill is suspended until this moment
        self.strikes = 0         # consecutive rejections (drives the backoff)

    # -- properties ---------------------------------------------------------
    @property
    def refill_rate(self) -> float:
        """Average tokens per second (refill_amount / refill_time)."""
        return self.refill_amount / self.refill_time

    @property
    def available(self) -> float:
        self._refill(time.monotonic())
        return self.state.tokens

    @property
    def is_locked(self) -> bool:
        return time.monotonic() < self.locked_until

    def retry_after(self) -> int:
        """Whole seconds until the cooldown lifts (``Retry-After`` header)."""
        return max(0, int(self.locked_until - time.monotonic()) + 1)

    # -- core ---------------------------------------------------------------
    def _refill(self, now: float) -> None:
        """Add tokens for every whole refill cycle that has elapsed."""
        if now < self.locked_until:
            # Cooldown active: suspend refill and re-anchor the clock so no
            # tokens accrue for the time spent locked.
            self.state.ts = now
            self.state.last_seen = now
            return

        elapsed = now - self.state.ts
        cycles = int(elapsed // self.refill_time)
        if cycles:
            self.state.tokens = min(
                self.capacity, self.state.tokens + cycles * self.refill_amount
            )
            # Advance by whole cycles only — the leftover fraction is kept, so
            # the long-run refill rate matches refill_amount / refill_time.
            self.state.ts += cycles * self.refill_time
        self.state.last_seen = now

    def consume(self, tokens: int = 1) -> bool:
        """Try to take *tokens* out of the bucket. False means "rejected"."""
        now = time.monotonic()
        self._refill(now)

        if self.state.tokens >= tokens:
            self.state.tokens -= tokens
            self.strikes = 0
            logger.debug(
                "%s Request[ACCEPTED] (tokens - %s)",
                _colorize(">", "accepted"),
                round(self.state.tokens, 3),
            )
            return True

        # Rejected -> start or extend the cooldown.
        if now >= self.locked_until:
            self.locked_until = now + self._next_cooldown()
        else:
            self.strikes += 1
            remaining = self.locked_until - now
            self.locked_until = now + max(remaining, self._next_cooldown())
        logger.debug(
            "%s Request[REJECTED] (tokens - %s, retry after %ss)",
            _colorize("!", "rejected"),
            round(self.state.tokens, 3),
            self.retry_after(),
        )
        return False

    def _next_cooldown(self) -> float:
        """Cooldown for the next rejection: 2s, 4s, 8s ... capped."""
        return min(self.base_cooldown * (2 ** min(self.strikes, 5)), self.max_cooldown)


class TokenBucketStore:
    """Holds one :class:`TokenBucket` per key, with pruning of idle buckets."""

    def __init__(
        self,
        capacity: int = 5,
        refill_amount: int = 5,
        refill_time: float = 30.0,
        base_cooldown: float = 2.0,
        max_cooldown: float = 30.0,
        max_buckets: int = 1024,
        idle_ttl: float = 3600.0,
    ) -> None:
        self.capacity = capacity
        self.refill_amount = refill_amount
        self.refill_time = refill_time
        self.base_cooldown = base_cooldown
        self.max_cooldown = max_cooldown
        self.max_buckets = max_buckets
        self.idle_ttl = idle_ttl
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def get_bucket(self, key: str) -> TokenBucket:
        """Return (creating if needed) the bucket for *key*."""
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(
                    capacity=self.capacity,
                    refill_amount=self.refill_amount,
                    refill_time=self.refill_time,
                    base_cooldown=self.base_cooldown,
                    max_cooldown=self.max_cooldown,
                )
                self._buckets[key] = bucket
            if len(self._buckets) > self.max_buckets:
                self._prune()
            return bucket

    def handle_request(self, key: str, tokens: int = 1) -> bool:
        """Port of the reference ``handleRequest``: True = accepted."""
        return self.get_bucket(key).consume(tokens)

    def _prune(self) -> None:
        """Drop buckets that have been idle for longer than ``idle_ttl``."""
        now = time.monotonic()
        stale = [
            key
            for key, bucket in self._buckets.items()
            if bucket.state.idle_seconds > self.idle_ttl
        ]
        for key in stale:
            del self._buckets[key]

    def reset(self) -> None:
        """Forget every bucket (used by the test suite)."""
        with self._lock:
            self._buckets.clear()

    def __len__(self) -> int:
        return len(self._buckets)


# Default store used by the application (one process, in-memory).
# For a multi-worker deployment swap this for a Redis-backed store.
store = TokenBucketStore()


def get_bucket(key: str) -> TokenBucket:
    """Convenience wrapper around the default store."""
    return store.get_bucket(key)


def reset_buckets() -> None:
    """Reset the default store (test helper)."""
    store.reset()
