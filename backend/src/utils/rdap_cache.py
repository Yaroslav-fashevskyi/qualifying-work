from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Optional, Dict, Any, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

import httpx

DB = Path(
    os.getenv("RDAP_DB_PATH", "")
    or (Path(__file__).resolve().parents[1] / "data" / "rdap.sqlite")
)
TTL = int(os.getenv("RDAP_CACHE_TTL_SEC", str(30 * 24 * 3600)))
RDAP_TIMEOUT = float(os.getenv("RDAP_TIMEOUT_SEC", "1.5"))
RDAP_ENDPOINTS = (
    "https://rdap.arin.net/registry/ip/{ip}",
    "https://rdap.db.ripe.net/ip/{ip}",
    "https://rdap.apnic.net/ip/{ip}",
    "https://rdap.lacnic.net/rdap/ip/{ip}",
    "https://rdap.afrinic.net/rdap/ip/{ip}",
)


def _conn() -> sqlite3.Connection:
    DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB, timeout=10)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("CREATE TABLE IF NOT EXISTS rdap(ip TEXT PRIMARY KEY, data TEXT, ts INT)")
    return c


def _read(ip: str) -> Optional[Dict[str, Any]]:
    c = _conn()
    try:
        row = c.execute("SELECT data, ts FROM rdap WHERE ip=?", (ip,)).fetchone()
        if not row:
            return None
        data, ts = row
        if time.time() - ts > TTL:
            return None
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            c.execute("DELETE FROM rdap WHERE ip=?", (ip,))
            c.commit()
            return None
    finally:
        c.close()


def _write(ip: str, data: Dict[str, Any]) -> None:
    c = _conn()
    try:
        c.execute(
            "REPLACE INTO rdap VALUES(?,?,?)", (ip, json.dumps(data), int(time.time()))
        )
        c.commit()
    finally:
        c.close()


def _pick_entity(
    entities: Iterable[Dict[str, Any]], roles: Iterable[str], default: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    entity_list = list(entities or [])
    for role in roles:
        for entity in entity_list:
            entity_roles = entity.get("roles") or []
            if role in entity_roles:
                return entity
    if default is not None:
        return default
    return entity_list[0] if entity_list else {}


def _vcard_field(entity: Dict[str, Any], name: str) -> Optional[str]:
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for entry in vcard[1]:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        field_name = str(entry[0] or "").lower()
        if field_name != name:
            continue
        value = entry[3]
        if isinstance(value, list):
            value = " ".join(str(part) for part in value if part)
        return str(value) if value else None
    return None


def _extract_asn(payload: Dict[str, Any]) -> Optional[str]:
    for key in ("arin_originas0_originautnums", "originAutnum", "autnums"):
        data = payload.get(key)
        if isinstance(data, list) and data:
            entry = data[0]
            if isinstance(entry, dict):
                if entry.get("handle"):
                    return str(entry["handle"])
                if entry.get("name"):
                    return str(entry["name"])
                if entry.get("startAutnum"):
                    return f"AS{entry['startAutnum']}"
        elif isinstance(data, dict):
            handle = data.get("handle")
            if handle:
                return str(handle)
    for entity in payload.get("entities") or []:
        handle = entity.get("handle")
        if isinstance(handle, str) and handle.upper().startswith("AS"):
            return handle
    return None


def _extract_range(payload: Dict[str, Any]) -> Optional[str]:
    cidrs = payload.get("cidr0_cidrs") or []
    if isinstance(cidrs, list) and cidrs:
        block = cidrs[0]
        if isinstance(block, dict):
            prefix = block.get("v4prefix") or block.get("v6prefix")
            length = block.get("length")
            if prefix and length is not None:
                return f"{prefix}/{length}"
    start = payload.get("startAddress")
    end = payload.get("endAddress")
    if start and end:
        return f"{start} - {end}"
    return None


def _event_date(payload: Dict[str, Any], action: str) -> Optional[str]:
    for event in payload.get("events") or []:
        if event.get("eventAction") == action and event.get("eventDate"):
            return str(event["eventDate"])
    return None


def _shape_rdap(payload: Dict[str, Any], source: str) -> Dict[str, Any]:
    entities = payload.get("entities") or []
    registrant = _pick_entity(entities, ("registrant", "administrative", "technical"))
    abuse = _pick_entity(entities, ("abuse",), default={})

    rdap_name = (
        _vcard_field(registrant, "fn")
        or _vcard_field(registrant, "org")
        or payload.get("name")
    )
    rdap_org = registrant.get("handle") or payload.get("handle")
    rdap_abuse = _vcard_field(abuse, "email")

    return {
        "rdap_name": rdap_name,
        "rdap_org": rdap_org,
        "rdap_source": source,
        "rdap_handle": payload.get("handle"),
        "rdap_range": _extract_range(payload),
        "rdap_type": payload.get("type"),
        "rdap_asn": _extract_asn(payload),
        "rdap_registered": _event_date(payload, "registration"),
        "rdap_abuse": rdap_abuse,
    }


def _fetch_one(url: str) -> Optional[Dict[str, Any]]:
    try:
        with httpx.Client(timeout=RDAP_TIMEOUT, follow_redirects=True) as client:
            response = client.get(url)
            if not response.is_success:
                return None
            shaped = _shape_rdap(response.json(), response.url.host or url.split("/")[2])
            if any(value is not None for value in shaped.values()):
                return shaped
    except (httpx.HTTPError, ValueError, json.JSONDecodeError):
        return None
    return None


def _fetch(ip: str) -> Optional[Dict[str, Any]]:
    urls = [template.format(ip=ip) for template in RDAP_ENDPOINTS]
    executor = ThreadPoolExecutor(max_workers=min(5, len(urls)))
    futures = [executor.submit(_fetch_one, url) for url in urls]
    try:
        iterator = as_completed(futures, timeout=max(RDAP_TIMEOUT * 2, 3.0))
        for future in iterator:
            result = future.result()
            if result:
                return result
    except TimeoutError:
        for future in futures:
            future.cancel()
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return None


def rdap_enrich(ip: str) -> Optional[Dict[str, Any]]:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
        return None

    data = _read(str(ip_obj))
    if data:
        return data
    fetched = _fetch(str(ip_obj))
    if fetched:
        _write(str(ip_obj), fetched)
    return fetched
