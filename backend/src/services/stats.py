from __future__ import annotations

from typing import Dict, Any
import time


class RuntimeStatsTracker:
    def __init__(self) -> None:
        self._stats: Dict[str, Any] = {
            "total_lookups": 0,
            "by_country": {},
            "since": int(time.time()),
        }

    def snapshot(self) -> Dict[str, Any]:
        return {
            "total_lookups": self._stats["total_lookups"],
            "by_country": dict(self._stats["by_country"]),
            "since": self._stats["since"],
        }

    def bump(self, payload: Dict[str, Any]) -> None:
        self._stats["total_lookups"] += 1
        country = payload.get("country_code")
        if country:
            counts = self._stats["by_country"]
            counts[country] = counts.get(country, 0) + 1
