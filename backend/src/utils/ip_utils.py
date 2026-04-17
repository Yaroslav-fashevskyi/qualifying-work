import asyncio
import ipaddress
from dataclasses import dataclass
from typing import Optional

from fastapi import Request


@dataclass(frozen=True)
class LookupTarget:
    query: str
    query_type: str
    ip: str | None = None
    domain: str | None = None


def is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def normalize_domain(value: str) -> str | None:
    raw = (value or "").strip().rstrip(".").lower()
    if not raw:
        return None
    try:
        return raw.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def is_domain_name(value: str) -> bool:
    normalized = normalize_domain(value)
    if not normalized or len(normalized) > 253:
        return False
    labels = normalized.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False
    return True


async def resolve_domain_ips(domain: str) -> list[str]:
    resolved: list[str] = []
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(domain, None)
        for info in infos:
            ip = info[4][0]
            if is_ip(ip) and ip not in resolved:
                resolved.append(ip)
    except Exception:
        return []
    return resolved


async def resolve_domain_to_ip(domain: str) -> Optional[str]:
    ips = await resolve_domain_ips(domain)
    for ip in ips:
        if ":" not in ip:
            return ip
    return ips[0] if ips else None


async def parse_query_target(q: str) -> LookupTarget | None:
    q = (q or "").strip()
    if not q:
        return None
    if is_ip(q):
        return LookupTarget(query=q, query_type="ip", ip=q)
    if is_domain_name(q):
        normalized = normalize_domain(q)
        if normalized:
            return LookupTarget(
                query=q,
                query_type="domain",
                domain=normalized,
            )
    return None


def client_ip(request: Request) -> str:
    for h in ("x-forwarded-for", "x-real-ip", "cf-connecting-ip"):
        if h in request.headers:
            val = request.headers[h].split(",")[0].strip()
            if is_ip(val):
                return val
    return request.client.host if request.client else "0.0.0.0"
