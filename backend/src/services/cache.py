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
    """Small in-process LRU cache with per-entry TTL and basic diagnostics."""

    def __init__(self, ttl_seconds: float, max_entries: int) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._storage: "OrderedDict[K, _Entry[V]]" = OrderedDict()
        self._hits = 0
        self._misses = 0

    def _now(self) -> float:
        return time.time()

    def _prune_expired(self, now: Optional[float] = None) -> None:
        ts = now if now is not None else self._now()
        expired_keys = [key for key, entry in self._storage.items() if entry.expires_at <= ts]
        for key in expired_keys:
            self._storage.pop(key, None)

    def get(self, key: K) -> Optional[V]:
        entry = self._storage.get(key)
        if entry is None:
            self._misses += 1
            return None
        if entry.expires_at <= self._now():
            self._storage.pop(key, None)
            self._misses += 1
            return None
        self._hits += 1
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

    def stats(self) -> dict[str, float | int]:
        total = self._hits + self._misses
        return {
            "ttl_seconds": self._ttl,
            "max_entries": self._max_entries,
            "size": len(self._storage),
            "hits": self._hits,
            "misses": self._misses,
            "hit_ratio": round(self._hits / total, 4) if total else 0,
        }
