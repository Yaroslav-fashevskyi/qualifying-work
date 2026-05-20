from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from fastapi import Request

ASN_RE = re.compile(r"^(?:as)?(?P<asn>[1-9][0-9]{0,9})$", re.IGNORECASE)


@dataclass(frozen=True)
class LookupTarget:
    query: str
    query_type: str
    ip: str | None = None
    domain: str | None = None
    asn: int | None = None
    prefix: str | None = None


def is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def clean_query_value(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""

    bracketless = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        return str(ipaddress.ip_address(bracketless))
    except ValueError:
        pass

    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        pass

    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    if parsed.hostname:
        raw = parsed.hostname
    else:
        raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if raw.startswith("[") and "]" in raw:
            raw = raw[1 : raw.index("]")]
        elif raw.count(":") == 1:
            host, maybe_port = raw.rsplit(":", 1)
            if maybe_port.isdigit():
                raw = host

    return raw.strip().rstrip(".")


def normalize_domain(value: str) -> str | None:
    raw = clean_query_value(value).lower()
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
    if labels[-1].isdigit():
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False
    return True


def parse_asn(value: str) -> int | None:
    cleaned = clean_query_value(value).replace(" ", "")
    match = ASN_RE.match(cleaned)
    if not match:
        return None
    asn = int(match.group("asn"))
    if asn > 4_294_967_295:
        return None
    return asn


def parse_prefix(value: str) -> str | None:
    cleaned = (value or "").strip()
    try:
        network = ipaddress.ip_network(cleaned, strict=False)
    except ValueError:
        return None
    if "/" not in cleaned:
        return None
    return str(network)


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
    original = (q or "").strip()
    cleaned = clean_query_value(original)
    if not cleaned:
        return None

    prefix = parse_prefix(original)
    if prefix:
        network = ipaddress.ip_network(prefix, strict=False)
        selected_ip = str(network.network_address)
        return LookupTarget(query=original, query_type="prefix", ip=selected_ip, prefix=prefix)

    if is_ip(cleaned):
        return LookupTarget(query=original, query_type="ip", ip=str(ipaddress.ip_address(cleaned)))

    asn = parse_asn(cleaned)
    if asn is not None:
        return LookupTarget(query=original, query_type="asn", asn=asn)

    if is_domain_name(cleaned):
        normalized = normalize_domain(cleaned)
        if normalized:
            return LookupTarget(query=original, query_type="domain", domain=normalized)
    return None


def client_ip(request: Request) -> str:
    for h in ("cf-connecting-ip", "x-real-ip", "x-forwarded-for"):
        if h in request.headers:
            val = request.headers[h].split(",")[0].strip()
            if is_ip(val):
                return val
    return request.client.host if request.client else "0.0.0.0"
