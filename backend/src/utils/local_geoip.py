import os
from pathlib import Path
from typing import Optional, Dict, Any
import geoip2.database

DATA_DIR = Path(
    os.getenv("GEOIP_DATA_DIR", "") or (Path(__file__).resolve().parents[1] / "data")
)
CITY_DB = DATA_DIR / "GeoLite2-City.mmdb"
ASN_DB = DATA_DIR / "GeoLite2-ASN.mmdb"

_city_reader = None
_asn_reader = None


def _try_open(p: Path):
    try:
        if p.exists() and p.is_file():
            return geoip2.database.Reader(str(p))
    except Exception:
        pass
    return None


def _city():
    global _city_reader
    if _city_reader is None:
        _city_reader = _try_open(CITY_DB)
    return _city_reader


def _asn():
    global _asn_reader
    if _asn_reader is None:
        _asn_reader = _try_open(ASN_DB)
    return _asn_reader


def geoip_lookup(ip: str) -> Optional[Dict[str, Any]]:
    c = _city()
    if not c:
        return None
    out: Dict[str, Any] = {"ip": ip, "source": "local-mmdb"}
    try:
        r = c.city(ip)
        out.update(
            {
                "city": r.city.name,
                "region": r.subdivisions.most_specific.name,
                "country_name": r.country.name,
                "country_code": r.country.iso_code,
                "latitude": r.location.latitude,
                "longitude": r.location.longitude,
                "timezone": r.location.time_zone,
            }
        )
    except Exception:
        pass
    a = _asn()
    if a:
        try:
            ar = a.asn(ip)
            out["org"] = (
                f"AS{ar.autonomous_system_number} {ar.autonomous_system_organization}"
            )
        except Exception:
            pass
    return out
