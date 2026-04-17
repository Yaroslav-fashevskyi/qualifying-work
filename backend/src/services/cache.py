from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Generic, Optional, TypeVar
import time


K = TypeVar("K")
V = TypeVar("V")


@dataclass
class _Entry(Generic[V]):
    value: V
    expires_at: float


class TTLCache(Generic[K, V]):
    """Simple LRU cache with TTL applied per entry."""

    def __init__(self, ttl_seconds: float, max_entries: int) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._storage: "OrderedDict[K, _Entry[V]]" = OrderedDict()

    def _now(self) -> float:
        return time.time()

    def _prune_expired(self, now: Optional[float] = None) -> None:
        ts = now if now is not None else self._now()
        while self._storage:
            key, entry = next(iter(self._storage.items()))
            if entry.expires_at > ts:
                break
            self._storage.popitem(last=False)

    def get(self, key: K) -> Optional[V]:
        entry = self._storage.get(key)
        if entry is None:
            return None
        if entry.expires_at <= self._now():
            self._storage.pop(key, None)
            return None
        self._storage.move_to_end(key)
        return entry.value

    def set(self, key: K, value: V) -> None:
        now = self._now()
        self._prune_expired(now)
        self._storage[key] = _Entry(value=value, expires_at=now + self._ttl)
        self._storage.move_to_end(key)
        while len(self._storage) > self._max_entries:
            self._storage.popitem(last=False)

    def clear(self) -> None:
        self._storage.clear()
