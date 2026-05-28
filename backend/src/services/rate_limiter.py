from __future__ import annotations

from collections import deque
from typing import Deque, Dict
import time


class RateLimitExceeded(Exception):
    """Raised when the rate limiter rejects a request."""


class SlidingWindowRateLimiter:
    def __init__(self, window_seconds: int, max_hits: int) -> None:
        self._window = window_seconds
        self._max_hits = max_hits
        self._hits: Dict[str, Deque[float]] = {}
        self._next_sweep = 0.0

    def _now(self) -> float:
        return time.time()

    def _sweep(self, cutoff: float) -> None:
        for key in list(self._hits.keys()):
            queue = self._hits.get(key)
            if not queue:
                continue
            while queue and queue[0] <= cutoff:
                queue.popleft()
            if not queue:
                self._hits.pop(key, None)

    def check(self, identifier: str, hits: int = 1) -> None:
        now = self._now()
        cutoff = now - self._window
        queue = self._hits.setdefault(identifier, deque())
        while queue and queue[0] <= cutoff:
            queue.popleft()
        hits = max(1, hits)
        if len(queue) + hits > self._max_hits:
            raise RateLimitExceeded
        for _ in range(hits):
            queue.append(now)
        if now >= self._next_sweep:
            self._sweep(cutoff)
            self._next_sweep = now + min(self._window, 120)

    def snapshot(self) -> dict[str, int]:
        return {
            "window_seconds": self._window,
            "max_hits": self._max_hits,
            "tracked_identifiers": len(self._hits),
        }
