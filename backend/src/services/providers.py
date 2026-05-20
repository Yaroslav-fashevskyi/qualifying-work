from __future__ import annotations

from typing import Dict, Any, Optional
import asyncio
import os
from pathlib import Path
import re
from urllib.parse import urljoin, urlparse

import httpx
import dns.exception
import dns.resolver


class ExternalProviders:
    COMMON_ORIGIN_HOSTNAMES = (
        "origin",
        "direct",
        "direct-connect",
        "cdn",
        "static",
        "assets",
        "media",
        "files",
        "img",
        "images",
        "server",
        "server1",
        "web",
        "web1",
        "app",
        "app1",
        "api",
        "backend",
        "panel",
        "cpanel",
        "host",
        "hosting",
    )
    SOURCE_PRIORITY = {
        "js": 90,
        "html": 80,
        "csp": 75,
        "txt": 70,
        "ct": 65,
        "mx": 55,
        "wordlist": 45,
        "heuristic": 35,
    }
    SOURCE_CONFIDENCE = {
        "js": 60,
        "html": 52,
        "csp": 48,
        "txt": 42,
        "ct": 46,
        "mx": 34,
        "wordlist": 30,
        "heuristic": 24,
    }
    HIGH_SIGNAL_RULES = {
        "origin",
        "direct",
        "direct-connect",
        "backend",
        "server",
        "server1",
        "web",
        "web1",
        "app",
        "app1",
        "api",
        "panel",
        "cpanel",
    }
    MAX_DISCOVERY_CANDIDATES = 24
    MAX_JS_ASSETS = 4
    MAX_HTML_CHARS = 250_000
    MAX_JS_CHARS = 180_000

    def __init__(self, timeout: float | None = None) -> None:
        if timeout is None:
            try:
                timeout = float(os.getenv("PROVIDER_TIMEOUT_SEC", "2.0"))
            except ValueError:
                timeout = 2.0
        self._timeout = max(0.5, timeout)
        self._headers = {"User-Agent": "ip-intelligence-backend/1.0"}
        self._wordlist_entries = self._load_optional_wordlist()

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        out: list[str] = []
        for value in values:
            item = (value or "").strip()
            if item and item not in out:
                out.append(item)
        return out

    def _load_optional_wordlist(self) -> list[str]:
        paths: list[Path] = []
        env_path = (os.getenv("ORIGIN_DISCOVERY_WORDLIST_PATH") or "").strip()
        if env_path:
            paths.append(Path(env_path))

        default_path = Path(__file__).resolve().parents[1] / "data" / "origin_wordlist.txt"
        if default_path.exists():
            paths.append(default_path)

        values: list[str] = []
        for path in paths:
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    item = line.strip().lower()
                    if not item or item.startswith("#"):
                        continue
                    values.append(item)
            except Exception:
                continue
        return self._dedupe(values)

    @staticmethod
    def _normalize_candidate_hostname(hostname: str, domain: str) -> str | None:
        value = (hostname or "").strip().lower().strip(".")
        if not value:
            return None
        if value.startswith("*."):
            value = value[2:]
        if value == domain:
            return None
        if value.endswith(f".{domain}"):
            return value
        return None

    def _expand_wordlist_entry(self, entry: str, domain: str) -> str | None:
        item = (entry or "").strip().lower().strip(".")
        if not item:
            return None
        if "." in item:
            return self._normalize_candidate_hostname(item, domain)
        return self._normalize_candidate_hostname(f"{item}.{domain}", domain)

    def _extract_same_domain_hostnames(self, text: str, domain: str) -> list[str]:
        if not text:
            return []
        normalized_text = (
            text.replace("\\u002f", "/")
            .replace("\\u002F", "/")
            .replace("\\/", "/")
            .replace("%2f", "/")
            .replace("%2F", "/")
        )
        pattern = re.compile(
            rf"(?<![a-z0-9-])(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+{re.escape(domain)}\.?",
            re.IGNORECASE,
        )
        matches = [
            match.group(0).strip().lower().strip(".")
            for match in pattern.finditer(normalized_text)
        ]
        normalized = [
            self._normalize_candidate_hostname(match, domain)
            for match in matches
        ]
        return self._dedupe([item for item in normalized if item])

    def _remember_candidate(
        self,
        store: Dict[str, Dict[str, Any]],
        domain: str,
        hostname: str,
        source: str,
        *,
        matched_rule: str | None = None,
        evidence: str | None = None,
    ) -> None:
        normalized = self._normalize_candidate_hostname(hostname, domain)
        if not normalized:
            return

        entry = store.setdefault(
            normalized,
            {
                "hostname": normalized,
                "matched_rule": None,
                "sources": [],
                "evidence": [],
            },
        )
        if source not in entry["sources"]:
            entry["sources"].append(source)

        if matched_rule and not entry["matched_rule"]:
            entry["matched_rule"] = matched_rule

        if evidence and evidence not in entry["evidence"] and len(entry["evidence"]) < 6:
            entry["evidence"].append(evidence)

    def _candidate_base_confidence(self, candidate: Dict[str, Any]) -> int:
        sources = candidate.get("sources") or []
        if not sources:
            return 20

        score = max(self.SOURCE_CONFIDENCE.get(source, 20) for source in sources)
        score += max(0, len(sources) - 1) * 12

        matched_rule = candidate.get("matched_rule")
        if matched_rule in self.HIGH_SIGNAL_RULES:
            score += 10

        hostname = str(candidate.get("hostname") or "")
        if any(token in hostname for token in ("origin", "direct", "backend", "internal", "server")):
            score += 6

        return min(score, 95)

    def _primary_source(self, candidate: Dict[str, Any]) -> str:
        sources = candidate.get("sources") or []
        if not sources:
            return "heuristic"
        return max(
            sources,
            key=lambda source: (self.SOURCE_PRIORITY.get(source, 0), source),
        )

    def _candidate_sort_key(self, candidate: Dict[str, Any]) -> tuple[int, int, str]:
        return (
            -self._candidate_base_confidence(candidate),
            -len(candidate.get("sources") or []),
            str(candidate.get("hostname") or ""),
        )

    @staticmethod
    def _should_seed_generated_candidates(
        domain: str, dns_profile: Dict[str, list[str]]
    ) -> bool:
        labels = [label for label in (domain or "").split(".") if label]
        if len(labels) <= 2:
            return True
        return bool((dns_profile.get("ns") or []) or (dns_profile.get("soa") or []))

    async def _fetch_text_document(
        self, client: httpx.AsyncClient, url: str, max_chars: int
    ) -> Dict[str, Any] | None:
        try:
            response = await client.get(url, follow_redirects=True)
            if not response.is_success:
                return None
            content_type = (response.headers.get("content-type") or "").lower()
            text = response.text[:max_chars]
            return {
                "url": str(response.url),
                "content_type": content_type,
                "headers": response.headers,
                "text": text,
            }
        except Exception:
            return None

    def _extract_script_urls(self, html: str, base_url: str, domain: str) -> list[str]:
        urls: list[str] = []
        pattern = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
        for raw in pattern.findall(html):
            url = urljoin(base_url, raw.strip())
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower().strip(".")
            if not parsed.scheme.startswith("http"):
                continue
            if hostname and hostname != domain and not hostname.endswith(f".{domain}"):
                continue
            urls.append(url)
        return self._dedupe(urls)[: self.MAX_JS_ASSETS]

    async def _discover_page_candidates(
        self, client: httpx.AsyncClient, domain: str
    ) -> list[tuple[str, str, str]]:
        page_urls = (f"https://{domain}/", f"http://{domain}/")
        findings: list[tuple[str, str, str]] = []

        document: Dict[str, Any] | None = None
        for url in page_urls:
            document = await self._fetch_text_document(client, url, self.MAX_HTML_CHARS)
            if document:
                break

        if not document:
            return findings

        html = str(document.get("text") or "")
        response_url = str(document.get("url") or "")
        for hostname in self._extract_same_domain_hostnames(html, domain):
            findings.append((hostname, "html", "Referenced from the landing page HTML or inline scripts."))

        for header_name in ("content-security-policy", "content-security-policy-report-only"):
            header_value = document.get("headers", {}).get(header_name)
            if not header_value:
                continue
            for hostname in self._extract_same_domain_hostnames(str(header_value), domain):
                findings.append((hostname, "csp", f"Referenced by the `{header_name}` header."))

        js_urls = self._extract_script_urls(html, response_url, domain)
        if not js_urls:
            return findings

        js_documents = await asyncio.gather(
            *[self._fetch_text_document(client, url, self.MAX_JS_CHARS) for url in js_urls],
            return_exceptions=True,
        )
        for js_url, js_document in zip(js_urls, js_documents):
            if not isinstance(js_document, dict):
                continue
            if "javascript" not in str(js_document.get("content_type") or "") and not js_url.endswith(".js"):
                continue
            js_text = str(js_document.get("text") or "")
            for hostname in self._extract_same_domain_hostnames(js_text, domain):
                findings.append((hostname, "js", f"Referenced by JavaScript asset `{urlparse(js_url).path or js_url}`."))

        return findings

    async def _discover_certificate_candidates(
        self, client: httpx.AsyncClient, domain: str
    ) -> list[str]:
        try:
            response = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
            )
            if not response.is_success:
                return []
            payload = response.json()
            if not isinstance(payload, list):
                return []
        except Exception:
            return []

        hostnames: list[str] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            name_value = str(item.get("name_value") or "")
            for raw_name in name_value.splitlines():
                normalized = self._normalize_candidate_hostname(raw_name, domain)
                if normalized:
                    hostnames.append(normalized)
        return self._dedupe(hostnames)

    async def _resolve_with_system_dns(
        self, domain: str, record_type: str
    ) -> list[str] | None:
        def _query() -> list[str] | None:
            try:
                answers = dns.resolver.resolve(
                    domain,
                    record_type,
                    lifetime=self._timeout,
                    search=False,
                )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return []
            except dns.exception.Timeout:
                return None
            except dns.resolver.NoNameservers:
                return None
            except Exception:
                return None

            values: list[str] = []
            for answer in answers:
                try:
                    values.append(answer.to_text().strip())
                except Exception:
                    continue
            return self._dedupe(values)

        return await asyncio.to_thread(_query)

    async def _fetch_dns_records(
        self, client: httpx.AsyncClient, domain: str, record_type: str
    ) -> list[str]:
        system_values = await self._resolve_with_system_dns(domain, record_type)
        if system_values is not None:
            return system_values

        try:
            response = await client.get(
                "https://dns.google/resolve",
                params={"name": domain, "type": record_type},
            )
            if not response.is_success:
                return []
            payload = response.json()
            if payload.get("Status") not in (0, None):
                return []
            answers = payload.get("Answer") or []
            values = [str(answer.get("data", "")).strip() for answer in answers]
            return self._dedupe(values)
        except Exception:
            return []

    async def fetch_ipapi(self, ip: str) -> Optional[Dict[str, Any]]:
        url = f"https://ipapi.co/{ip}/json/"
        async with httpx.AsyncClient(
            timeout=self._timeout, headers=self._headers
        ) as client:
            response = await client.get(url)
            if not response.is_success:
                return None
            payload = response.json()
            return {
                "ip": payload.get("ip"),
                "city": payload.get("city"),
                "region": payload.get("region"),
                "country_name": payload.get("country_name"),
                "country_code": payload.get("country"),
                "org": payload.get("org") or payload.get("asn"),
                "latitude": payload.get("latitude"),
                "longitude": payload.get("longitude"),
                "timezone": payload.get("timezone"),
                "source": "ipapi.co",
            }

    async def fetch_ipwhois(self, ip: str) -> Optional[Dict[str, Any]]:
        url = f"https://ipwho.is/{ip}"
        async with httpx.AsyncClient(
            timeout=self._timeout, headers=self._headers
        ) as client:
            response = await client.get(url)
            if not response.is_success:
                return None
            payload = response.json()
            if not payload.get("success", True):
                return None
            connection = payload.get("connection") or {}
            return {
                "ip": payload.get("ip"),
                "city": payload.get("city"),
                "region": payload.get("region"),
                "country_name": payload.get("country"),
                "country_code": payload.get("country_code"),
                "org": connection.get("org"),
                "latitude": payload.get("latitude"),
                "longitude": payload.get("longitude"),
                "timezone": payload.get("timezone"),
                "source": "ipwho.is",
            }

    async def online_fallback(self, ip: str) -> Dict[str, Any]:
        responses = await asyncio.gather(
            self.fetch_ipapi(ip), self.fetch_ipwhois(ip), return_exceptions=True
        )
        for response in responses:
            if isinstance(response, dict) and response:
                return response
        return {}


    async def fetch_asn_overview(self, asn: int) -> Optional[Dict[str, Any]]:
        url = "https://stat.ripe.net/data/as-overview/data.json"
        async with httpx.AsyncClient(timeout=self._timeout, headers=self._headers) as client:
            response = await client.get(url, params={"resource": f"AS{asn}"})
            if not response.is_success:
                return None
            payload = response.json()

        data = payload.get("data") or {}
        holder = data.get("holder") or data.get("name")
        return {
            "asn": asn,
            "holder": holder,
            "name": data.get("name") or holder,
            "country_code": data.get("country_code"),
            "registry": data.get("rir"),
            "allocated": data.get("allocated"),
            "source": "ripe-stat",
        }

    async def fetch_asn_prefixes(self, asn: int) -> list[str]:
        url = "https://stat.ripe.net/data/announced-prefixes/data.json"
        try:
            async with httpx.AsyncClient(timeout=self._timeout, headers=self._headers) as client:
                response = await client.get(url, params={"resource": f"AS{asn}"})
                if not response.is_success:
                    return []
                payload = response.json()
        except Exception:
            return []

        prefixes = []
        for item in (payload.get("data") or {}).get("prefixes") or []:
            prefix = item.get("prefix") if isinstance(item, dict) else None
            if prefix:
                prefixes.append(str(prefix))
        return self._dedupe(prefixes)

    async def asn_profile(self, asn: int) -> Dict[str, Any]:
        overview, prefixes = await asyncio.gather(
            self.fetch_asn_overview(asn),
            self.fetch_asn_prefixes(asn),
            return_exceptions=True,
        )
        profile: Dict[str, Any] = {"asn": asn, "prefixes": []}
        if isinstance(overview, dict):
            profile.update(overview)
        else:
            profile.update({"source": "asn-local", "holder": None, "name": None})
        if isinstance(prefixes, list):
            profile["prefixes"] = prefixes[:250]
        return profile

    async def domain_dns_profile(self, domain: str) -> Dict[str, list[str]]:
        record_types = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")
        async with httpx.AsyncClient(
            timeout=self._timeout, headers=self._headers
        ) as client:
            results = await asyncio.gather(
                *[
                    self._fetch_dns_records(client, domain, record_type)
                    for record_type in record_types
                ],
                return_exceptions=True,
            )

        profile: Dict[str, list[str]] = {
            "a": [],
            "aaaa": [],
            "cname": [],
            "mx": [],
            "ns": [],
            "txt": [],
            "caa": [],
            "soa": [],
        }
        for record_type, result in zip(record_types, results):
            if isinstance(result, list):
                profile[record_type.lower()] = result
        return profile

    async def _hostname_dns_profile(
        self, client: httpx.AsyncClient, hostname: str
    ) -> Dict[str, list[str]]:
        record_types = ("A", "AAAA", "CNAME")
        results = await asyncio.gather(
            *[
                self._fetch_dns_records(client, hostname, record_type)
                for record_type in record_types
            ],
            return_exceptions=True,
        )
        profile = {"a": [], "aaaa": [], "cname": []}
        for record_type, result in zip(record_types, results):
            if isinstance(result, list):
                profile[record_type.lower()] = result
        return profile

    @staticmethod
    def _mx_hostname(value: str) -> str | None:
        raw = (value or "").strip()
        if not raw:
            return None
        parts = raw.split()
        candidate = parts[-1].rstrip(".")
        return candidate.lower() if candidate else None

    async def discover_origin_candidates(
        self, domain: str, dns_profile: Dict[str, list[str]]
    ) -> list[Dict[str, Any]]:
        candidate_map: Dict[str, Dict[str, Any]] = {}
        include_generated_guesses = self._should_seed_generated_candidates(
            domain, dns_profile
        )

        if include_generated_guesses:
            for label in self.COMMON_ORIGIN_HOSTNAMES:
                self._remember_candidate(
                    candidate_map,
                    domain,
                    f"{label}.{domain}",
                    "heuristic",
                    matched_rule=label,
                    evidence=f"Generated from the built-in `{label}` hostname heuristic.",
                )

            for entry in self._wordlist_entries:
                hostname = self._expand_wordlist_entry(entry, domain)
                if hostname:
                    self._remember_candidate(
                        candidate_map,
                        domain,
                        hostname,
                        "wordlist",
                        evidence="Generated from the optional operator wordlist.",
                    )

        for mx_record in dns_profile.get("mx") or []:
            hostname = self._mx_hostname(mx_record)
            if hostname:
                self._remember_candidate(
                    candidate_map,
                    domain,
                    hostname,
                    "mx",
                    evidence="Derived from an MX target in the apex DNS records.",
                )

        for txt_record in dns_profile.get("txt") or []:
            for hostname in self._extract_same_domain_hostnames(txt_record, domain):
                self._remember_candidate(
                    candidate_map,
                    domain,
                    hostname,
                    "txt",
                    evidence="Referenced inside a TXT/SPF record.",
                )

        async with httpx.AsyncClient(
            timeout=self._timeout, headers=self._headers
        ) as client:
            ct_result, page_result = await asyncio.gather(
                self._discover_certificate_candidates(client, domain),
                self._discover_page_candidates(client, domain),
                return_exceptions=True,
            )

            if isinstance(ct_result, list):
                for hostname in ct_result:
                    self._remember_candidate(
                        candidate_map,
                        domain,
                        hostname,
                        "ct",
                        evidence="Observed in certificate transparency logs.",
                    )

            if isinstance(page_result, list):
                for hostname, source, evidence in page_result:
                    self._remember_candidate(
                        candidate_map,
                        domain,
                        hostname,
                        source,
                        evidence=evidence,
                    )

            ranked_candidates = sorted(
                candidate_map.values(),
                key=self._candidate_sort_key,
            )[: self.MAX_DISCOVERY_CANDIDATES]

            results = await asyncio.gather(
                *[
                    self._hostname_dns_profile(client, str(candidate.get("hostname") or ""))
                    for candidate in ranked_candidates
                ],
                return_exceptions=True,
            )

        output: list[Dict[str, Any]] = []
        for candidate, result in zip(ranked_candidates, results):
            dns_profile_for_host = (
                result
                if isinstance(result, dict)
                else {"a": [], "aaaa": [], "cname": []}
            )
            resolved_ips = self._dedupe(
                (dns_profile_for_host.get("a") or [])
                + (dns_profile_for_host.get("aaaa") or [])
            )
            output.append(
                {
                    "hostname": candidate.get("hostname"),
                    "source": self._primary_source(candidate),
                    "sources": sorted(
                        candidate.get("sources") or [],
                        key=lambda source: (-self.SOURCE_PRIORITY.get(source, 0), source),
                    ),
                    "matched_rule": candidate.get("matched_rule"),
                    "evidence": candidate.get("evidence") or [],
                    "confidence": self._candidate_base_confidence(candidate),
                    "dns": dns_profile_for_host,
                    "resolved_ips": resolved_ips,
                }
            )

        output.sort(key=lambda item: (-int(item.get("confidence") or 0), str(item.get("hostname") or "")))
        return output
