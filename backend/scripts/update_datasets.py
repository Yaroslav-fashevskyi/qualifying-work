from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import httpx

DATA = Path(__file__).resolve().parents[1] / "src" / "data"
MANIFEST = DATA / "sources_manifest.json"
GITHUB_API = "https://api.github.com"
USER_AGENT = "ip-lookup-service-dataset-sync/1.0"

TOR_URLS = [
    "https://check.torproject.org/torbulkexitlist",
    "https://www.dan.me.uk/torlist/",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_entry(value: str) -> str | None:
    raw = (value or "").strip()
    if not raw or raw.startswith("#"):
        return None
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return None


def parse_plain_list(text: str) -> set[str]:
    entries: set[str] = set()
    for line in text.splitlines():
        normalized = _normalize_entry(line)
        if normalized:
            entries.add(normalized)
    return entries


def parse_semicolon_list(text: str, min_confidence: float = 0.0) -> set[str]:
    entries: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lower().startswith("ip_address;"):
            continue
        parts = [part.strip() for part in stripped.split(";")]
        if not parts:
            continue
        if len(parts) > 2:
            try:
                confidence = float(parts[2])
            except ValueError:
                confidence = 0.0
            if confidence < min_confidence:
                continue
        normalized = _normalize_entry(parts[0])
        if normalized:
            entries.add(normalized)
    return entries


def sort_entries(entries: set[str]) -> list[str]:
    def key(value: str) -> tuple[int, int, int, str]:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            return (net.version, int(net.network_address), net.prefixlen, value)
        ip_obj = ipaddress.ip_address(value)
        suffix = 32 if ip_obj.version == 4 else 128
        return (ip_obj.version, int(ip_obj), suffix, value)

    return sorted(entries, key=key)


@dataclass(frozen=True)
class GitHubSource:
    name: str
    category: str
    owner: str
    repo: str
    path: str
    description: str
    parser_name: str
    min_confidence: float = 0.0

    @property
    def key(self) -> str:
        return f"github:{self.owner}/{self.repo}:{self.path}"

    @property
    def api_contents_url(self) -> str:
        return f"{GITHUB_API}/repos/{self.owner}/{self.repo}/contents/{self.path}"

    @property
    def api_license_url(self) -> str:
        return f"{GITHUB_API}/repos/{self.owner}/{self.repo}/license"

    @property
    def browser_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}/blob/main/{self.path}"

    @property
    def repo_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"


@dataclass
class SourceState:
    key: str
    name: str
    category: str
    source_url: str
    repo_url: str
    status: str
    entries: int
    license_spdx_id: str | None = None
    license_name: str | None = None
    license_text_hash: str | None = None
    content_etag: str | None = None
    license_etag: str | None = None
    last_synced_at: str | None = None
    notes: str | None = None


PARSERS: dict[str, Callable[[str], set[str]]] = {
    "plain": parse_plain_list,
}

GITHUB_SOURCES = [
    GitHubSource(
        name="x4b-vpn-ipv4",
        category="vpn",
        owner="X4BNet",
        repo="lists_vpn",
        path="output/vpn/ipv4.txt",
        description="Curated VPN prefixes",
        parser_name="plain",
    ),
    GitHubSource(
        name="x4b-datacenter-ipv4",
        category="datacenter",
        owner="X4BNet",
        repo="lists_vpn",
        path="output/datacenter/ipv4.txt",
        description="VPN and datacenter prefixes",
        parser_name="plain",
    ),
    GitHubSource(
        name="avastel-proxy-8days",
        category="proxy",
        owner="antoinevastel",
        repo="avastel-bot-ips-lists",
        path="avastel-proxy-bot-ips-blocklist-8days.txt",
        description="Verified proxy-bot CIDRs",
        parser_name="avastel",
        min_confidence=0.95,
    ),
    GitHubSource(
        name="ipsum-level-3",
        category="threat",
        owner="stamparm",
        repo="ipsum",
        path="levels/3.txt",
        description="High-confidence malicious IPs seen on 3+ lists",
        parser_name="plain",
    ),
]

OUTPUT_PATHS = {
    "tor": DATA / "tor.txt",
    "vpn": DATA / "vpn.txt",
    "proxy": DATA / "proxy.txt",
    "datacenter": DATA / "datacenters.txt",
    "threat": DATA / "threat.txt",
}


def _parser_for(source: GitHubSource) -> Callable[[str], set[str]]:
    if source.parser_name == "avastel":
        return lambda text: parse_semicolon_list(text, min_confidence=source.min_confidence)
    return PARSERS[source.parser_name]


def _load_manifest() -> dict:
    if not MANIFEST.exists():
        return {"generated_at": None, "sources": {}, "outputs": {}}
    try:
        return json.loads(MANIFEST.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"generated_at": None, "sources": {}, "outputs": {}}


def _github_headers(accept: str, etag: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": accept,
        "User-Agent": USER_AGENT,
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if etag:
        headers["If-None-Match"] = etag
    return headers


def _fetch_license(client: httpx.Client, source: GitHubSource, previous: dict) -> dict:
    headers = _github_headers(
        "application/vnd.github+json", previous.get("license_etag")
    )
    response = client.get(source.api_license_url, headers=headers)
    if response.status_code == 304:
        return {
            "status": "not_modified",
            "spdx_id": previous.get("license_spdx_id"),
            "license_name": previous.get("license_name"),
            "license_text_hash": previous.get("license_text_hash"),
            "etag": previous.get("license_etag"),
        }
    if response.status_code == 404:
        return {
            "status": "missing",
            "spdx_id": None,
            "license_name": None,
            "license_text_hash": None,
            "etag": response.headers.get("ETag"),
        }
    response.raise_for_status()
    payload = response.json()
    content = payload.get("content") or ""
    encoding = payload.get("encoding")
    decoded = b""
    if content and encoding == "base64":
        decoded = base64.b64decode(content)
    return {
        "status": "updated",
        "spdx_id": payload.get("license", {}).get("spdx_id"),
        "license_name": payload.get("license", {}).get("name"),
        "license_text_hash": hashlib.sha256(decoded).hexdigest() if decoded else None,
        "etag": response.headers.get("ETag"),
    }


def _fetch_content(client: httpx.Client, source: GitHubSource, previous: dict) -> tuple[str, str | None]:
    headers = _github_headers(
        "application/vnd.github.raw", previous.get("content_etag")
    )
    response = client.get(source.api_contents_url, headers=headers)
    if response.status_code == 304:
        return "not_modified", None
    response.raise_for_status()
    return response.headers.get("ETag") or "", response.text


def sync_github_sources(
    categories: set[str] | None = None,
    dry_run: bool = False,
    allow_no_license: bool = False,
) -> tuple[dict[str, set[str]], dict[str, dict]]:
    manifest = _load_manifest()
    previous_sources = manifest.get("sources", {})
    category_entries = {category: set() for category in OUTPUT_PATHS if category != "tor"}
    source_states: dict[str, dict] = {}

    with httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=True) as client:
        for source in GITHUB_SOURCES:
            if categories is not None and source.category not in categories:
                continue

            previous = previous_sources.get(source.key, {})
            state = SourceState(
                key=source.key,
                name=source.name,
                category=source.category,
                source_url=source.browser_url,
                repo_url=source.repo_url,
                status="skipped",
                entries=0,
            )
            try:
                license_info = _fetch_license(client, source, previous)
                state.license_spdx_id = license_info.get("spdx_id")
                state.license_name = license_info.get("license_name")
                state.license_text_hash = license_info.get("license_text_hash")
                state.license_etag = license_info.get("etag")
                if not state.license_spdx_id or state.license_spdx_id == "NOASSERTION":
                    if allow_no_license:
                        state.notes = "Proceeding without SPDX because allow_no_license is enabled"
                    else:
                        state.status = "disabled_no_license"
                        state.notes = "Missing SPDX license metadata"
                        state.last_synced_at = _utc_now()
                        source_states[source.key] = asdict(state)
                        continue

                content_etag, body = _fetch_content(client, source, previous)
                if body is None:
                    cached_output = OUTPUT_PATHS[source.category]
                    if cached_output.exists():
                        category_entries[source.category].update(
                            parse_plain_list(cached_output.read_text(encoding="utf-8"))
                        )
                    state.status = "not_modified"
                    state.entries = len(category_entries[source.category])
                    state.content_etag = previous.get("content_etag") or content_etag
                    state.last_synced_at = _utc_now()
                    source_states[source.key] = asdict(state)
                    continue

                parser = _parser_for(source)
                entries = parser(body)
                category_entries[source.category].update(entries)
                state.status = "dry_run" if dry_run else "updated"
                state.entries = len(entries)
                state.content_etag = content_etag
                state.last_synced_at = _utc_now()
            except httpx.HTTPError as exc:
                state.status = "error"
                state.notes = str(exc)
                state.last_synced_at = _utc_now()
            source_states[source.key] = asdict(state)

    return category_entries, source_states


def update_tor() -> set[str]:
    entries: set[str] = set()
    with httpx.Client(timeout=20.0, follow_redirects=True) as client:
        for url in TOR_URLS:
            try:
                response = client.get(url, headers={"User-Agent": USER_AGENT})
                response.raise_for_status()
            except httpx.HTTPError:
                continue
            entries.update(parse_plain_list(response.text))
    return entries


def write_outputs(
    entries_by_category: dict[str, set[str]],
    source_states: dict[str, dict],
    dry_run: bool,
    selected: set[str],
) -> None:
    existing = _load_manifest()
    outputs = dict(existing.get("outputs", {}))
    categories = selected or set(entries_by_category)

    for category, entries in entries_by_category.items():
        if category not in categories:
            continue
        path = OUTPUT_PATHS[category]
        sorted_entries = sort_entries(entries)
        if not sorted_entries and path.exists():
            continue
        outputs[category] = {"path": str(path.name), "entries": len(sorted_entries)}
        if not dry_run:
            path.write_text("\n".join(sorted_entries), encoding="utf-8")

    manifest = {
        "generated_at": _utc_now(),
        "sources": {**existing.get("sources", {}), **source_states},
        "outputs": outputs,
    }
    if not dry_run:
        MANIFEST.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Refresh local threat-intel datasets")
    parser.add_argument(
        "--only",
        action="append",
        choices=sorted(OUTPUT_PATHS),
        help="Refresh only the selected category. May be provided multiple times.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and parse sources without writing output files.",
    )
    parser.add_argument(
        "--allow-no-license",
        action="store_true",
        help="Allow GitHub sources that do not expose SPDX metadata via the license API.",
    )
    args = parser.parse_args()

    DATA.mkdir(parents=True, exist_ok=True)
    selected = set(args.only or [])

    entries_by_category = {key: set() for key in OUTPUT_PATHS}
    source_states: dict[str, dict] = {}

    github_categories = selected - {"tor"} if selected else None
    github_entries, github_states = sync_github_sources(
        categories=github_categories,
        dry_run=args.dry_run,
        allow_no_license=args.allow_no_license,
    )
    entries_by_category.update(github_entries)
    source_states.update(github_states)

    if not selected or "tor" in selected:
        tor_entries = update_tor()
        entries_by_category["tor"] = tor_entries
        source_states["tor:direct"] = asdict(
            SourceState(
                key="tor:direct",
                name="tor-direct",
                category="tor",
                source_url=",".join(TOR_URLS),
                repo_url="https://www.torproject.org/",
                status="dry_run" if args.dry_run else "updated",
                entries=len(tor_entries),
                last_synced_at=_utc_now(),
            )
        )

    write_outputs(entries_by_category, source_states, args.dry_run, selected)

    for category in sorted(OUTPUT_PATHS):
        if selected and category not in selected:
            continue
        count = len(entries_by_category[category])
        print(f"{category}: {count} entries")
    print("manifest:", MANIFEST)


if __name__ == "__main__":
    main()
