from __future__ import annotations

import csv
import ipaddress
import os
import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

from ipaddress import summarize_address_range

DATA_DIR = Path(
    os.getenv("SEC_LISTS_DIR", "") or (Path(__file__).resolve().parents[1] / "data")
)
TOR = DATA_DIR / "tor.txt"
VPN = DATA_DIR / "vpn.txt"
PROXY = DATA_DIR / "proxy.txt"
I2P = DATA_DIR / "i2p.txt"
THREAT = DATA_DIR / "threat.txt"
DATACENTERS_CSV = DATA_DIR / "datacenters.csv"
DATACENTERS_TXT = DATA_DIR / "datacenters.txt"
_RANGE_RE = re.compile(r"([0-9a-fA-F:\.]+)\s*-\s*([0-9a-fA-F:\.]+)")


@dataclass(frozen=True)
class RangeIndex:
    starts_v4: tuple[int, ...]
    ranges_v4: tuple[tuple[int, int], ...]
    starts_v6: tuple[int, ...]
    ranges_v6: tuple[tuple[int, int], ...]

    def contains(self, value: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(value)
        except ValueError:
            return False
        ranges = self.ranges_v4 if ip_obj.version == 4 else self.ranges_v6
        starts = self.starts_v4 if ip_obj.version == 4 else self.starts_v6
        if not ranges:
            return False
        number = int(ip_obj)
        idx = bisect_right(starts, number) - 1
        if idx < 0:
            return False
        return number <= ranges[idx][1]


def _load(path: Path) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    if not path.exists():
        return nets
    for line in path.read_text(encoding="utf-8").splitlines():
        normalized = line.strip()
        if not normalized or normalized.startswith("#"):
            continue
        try:
            if "/" not in normalized:
                ip_obj = ipaddress.ip_address(normalized)
                suffix = "/32" if ip_obj.version == 4 else "/128"
                nets.append(ipaddress.ip_network(f"{normalized}{suffix}", strict=False))
            else:
                nets.append(ipaddress.ip_network(normalized, strict=False))
        except ValueError:
            continue
    return nets


def _nets_from_value(value: str) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    if not value:
        return nets
    text = value.strip().strip('"').strip("'")
    if not text:
        return nets
    text = text.replace("–", "-")
    for match in _RANGE_RE.findall(text):
        start, end = match
        try:
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)
        except ValueError:
            continue
        for net in summarize_address_range(start_ip, end_ip):
            nets.append(net)
    remainder = _RANGE_RE.sub(" ", text)
    for sep in (",", ";", "|"):
        remainder = remainder.replace(sep, " ")
    for token in remainder.split():
        token = token.strip()
        if not token or token == "-":
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
            continue
        except ValueError:
            pass
        try:
            ip_obj = ipaddress.ip_address(token)
            suffix = "/32" if ip_obj.version == 4 else "/128"
            nets.append(ipaddress.ip_network(f"{token}{suffix}", strict=False))
        except ValueError:
            continue
    return nets


def _load_datacenters_csv(path: Path) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    if not path.exists():
        return nets
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            candidate_keys = (
                "cidr",
                "network",
                "ip_range",
                "range",
                "ip",
                "ip_address",
                "prefix",
            )
            for row in reader:
                values = []
                for key in candidate_keys:
                    raw_value = row.get(key)
                    if raw_value:
                        values.append(raw_value)
                if not values:
                    values = list(row.values())
                for raw_value in values:
                    nets.extend(_nets_from_value(raw_value))
    except Exception:
        return []
    return nets


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if not merged:
            merged.append((start, end))
            continue
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
            continue
        merged.append((start, end))
    return merged


def _compile_index(nets: list[ipaddress._BaseNetwork]) -> RangeIndex:
    ranges_v4: list[tuple[int, int]] = []
    ranges_v6: list[tuple[int, int]] = []
    for net in nets:
        current = ranges_v4 if net.version == 4 else ranges_v6
        current.append((int(net.network_address), int(net.broadcast_address)))
    merged_v4 = tuple(_merge_ranges(ranges_v4))
    merged_v6 = tuple(_merge_ranges(ranges_v6))
    return RangeIndex(
        starts_v4=tuple(start for start, _ in merged_v4),
        ranges_v4=merged_v4,
        starts_v6=tuple(start for start, _ in merged_v6),
        ranges_v6=merged_v6,
    )


_tor = _compile_index(_load(TOR))
_vpn = _compile_index(_load(VPN))
_proxy = _compile_index(_load(PROXY))
_i2p = _compile_index(_load(I2P))
_threat = _compile_index(_load(THREAT))
_datacenters = _compile_index(_load_datacenters_csv(DATACENTERS_CSV) + _load(DATACENTERS_TXT))


def security_flags(ip: str) -> dict[str, bool]:
    return {
        "vpn": _vpn.contains(ip),
        "proxy": _proxy.contains(ip),
        "tor": _tor.contains(ip),
        "i2p": _i2p.contains(ip),
        "datacenter": _datacenters.contains(ip),
        "threat": _threat.contains(ip),
    }
