from __future__ import annotations

import socket
from functools import lru_cache
from typing import Optional


@lru_cache(maxsize=2048)
def reverse_dns(ip: str) -> Optional[str]:
    """Resolve PTR record; cache results to avoid repeated lookups."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.rstrip(".")
    except (socket.herror, socket.gaierror):
        return None
    except Exception:
        return None
