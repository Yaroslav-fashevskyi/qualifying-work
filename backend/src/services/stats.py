from __future__ import annotations

from typing import Dict, Any
import time


class RuntimeStatsTracker:
    def __init__(self) -> None:
        self._stats: Dict[str, Any] = {
            "total_lookups": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "response_ms_total": 0,
            "by_country": {},
            "by_query_type": {},
            "security_hits": {},
            "since": int(time.time()),
        }

    def snapshot(self) -> Dict[str, Any]:
        total = self._stats["total_lookups"]
        hits = self._stats["cache_hits"]
        return {
            "total_lookups": total,
            "cache_hits": hits,
            "cache_misses": self._stats["cache_misses"],
            "cache_hit_ratio": round(hits / total, 4) if total else 0,
            "avg_response_ms": round(self._stats["response_ms_total"] / total, 2) if total else 0,
            "by_country": dict(self._stats["by_country"]),
            "by_query_type": dict(self._stats["by_query_type"]),
            "security_hits": dict(self._stats["security_hits"]),
            "since": self._stats["since"],
        }

    def bump(self, payload: Dict[str, Any]) -> None:
        self._stats["total_lookups"] += 1

        if payload.get("cached"):
            self._stats["cache_hits"] += 1
        else:
            self._stats["cache_misses"] += 1

        response_time_ms = payload.get("response_time_ms")
        if isinstance(response_time_ms, (int, float)):
            self._stats["response_ms_total"] += float(response_time_ms)

        country = payload.get("country_code")
        if country:
            counts = self._stats["by_country"]
            counts[country] = counts.get(country, 0) + 1

        query_type = payload.get("query_type") or "unknown"
        query_counts = self._stats["by_query_type"]
        query_counts[query_type] = query_counts.get(query_type, 0) + 1

        security = payload.get("security") or {}
        if isinstance(security, dict):
            for key, value in security.items():
                if value:
                    security_counts = self._stats["security_hits"]
                    security_counts[key] = security_counts.get(key, 0) + 1
