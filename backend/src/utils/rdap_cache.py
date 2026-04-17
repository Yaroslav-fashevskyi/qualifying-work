import sqlite3
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any, Iterable

import httpx

DB = Path(__file__).resolve().parents[1] / "data" / "rdap.sqlite"
TTL = 30 * 24 * 3600


def _conn():
    DB.parent.mkdir(exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS rdap(ip TEXT PRIMARY KEY, data TEXT, ts INT)")
    return c


def _read(ip):
    c = _conn()
    r = c.execute("SELECT data, ts FROM rdap WHERE ip=?", (ip,)).fetchone()
    c.close()
    if not r:
        return None
    data, ts = r
    if time.time() - ts > TTL:
        return None
    return json.loads(data)


def _write(ip, data):
    c = _conn()
    c.execute(
        "REPLACE INTO rdap VALUES(?,?,?)", (ip, json.dumps(data), int(time.time()))
    )
    c.commit()
    c.close()


def _pick_entity(
    entities: Iterable[Dict[str, Any]], roles: Iterable[str], default: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    for role in roles:
        for entity in entities or []:
            entity_roles = entity.get("roles") or []
            if role in entity_roles:
                return entity
    if default is not None:
        return default
    return (entities or [None])[0] or {}


def _vcard_field(entity: Dict[str, Any], name: str) -> Optional[str]:
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for entry in vcard[1]:
        if not entry or entry[0].lower() != name:
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
                    return entry["handle"]
                if entry.get("name"):
                    return entry["name"]
                if entry.get("startAutnum"):
                    return f"AS{entry['startAutnum']}"
        elif isinstance(data, dict):
            handle = data.get("handle")
            if handle:
                return handle
    for entity in payload.get("entities") or []:
        handle = entity.get("handle")
        if isinstance(handle, str) and handle.upper().startswith("AS"):
            return handle
    return None


def _extract_range(payload: Dict[str, Any]) -> Optional[str]:
    cidrs = payload.get("cidr0_cidrs") or []
    if isinstance(cidrs, list) and cidrs:
        block = cidrs[0]
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
            return event["eventDate"]
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


def _fetch(ip):
    urls = [
        f"https://rdap.arin.net/registry/ip/{ip}",
        f"https://rdap.db.ripe.net/ip/{ip}",
        f"https://rdap.apnic.net/ip/{ip}",
    ]
    with httpx.Client(timeout=8.0) as client:
        for u in urls:
            try:
                r = client.get(u)
                if r.is_success:
                    shaped = _shape_rdap(r.json(), u.split("/")[2])
                    if any(shaped.values()):
                        return shaped
            except httpx.HTTPError:
                continue
    return None


def rdap_enrich(ip) -> Optional[Dict[str, Any]]:
    data = _read(ip)
    if data:
        return data
    fetched = _fetch(ip)
    if fetched:
        _write(ip, fetched)
    return fetched
