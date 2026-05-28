from __future__ import annotations

from typing import Dict, Any
import asyncio
import ipaddress
import re
import time

from ..models import LookupResponse, SecurityFlags
from ..utils.local_geoip import geoip_lookup
from ..utils.security_lists import security_flags
from ..utils.ip_utils import LookupTarget, resolve_domain_to_ip
from ..utils.rdap_cache import rdap_enrich
from ..utils.rdns import reverse_dns
from .cache import TTLCache
from .history import HistoryService
from .stats import RuntimeStatsTracker
from .providers import ExternalProviders


CDN_PROVIDER_HINTS = {
    "cloudflare": "Cloudflare",
    "cloudfront": "CloudFront",
    "amazon": "Amazon CloudFront/AWS",
    "fastly": "Fastly",
    "akamai": "Akamai",
    "edgesuite": "Akamai",
    "edgekey": "Akamai",
    "imperva": "Imperva",
    "incapsula": "Imperva",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "bunny": "Bunny",
    "stackpath": "StackPath",
    "sucuri": "Sucuri",
    "google": "Google",
}

NS_PROVIDER_HINTS = {
    "cloudflare.com": "Cloudflare",
    "awsdns": "AWS Route 53",
    "akam.net": "Akamai",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "vercel-dns": "Vercel",
    "netlifydns": "Netlify",
    "bunnydns": "Bunny",
}

RISK_WEIGHTS = {
    "threat": 75,
    "tor": 55,
    "proxy": 45,
    "vpn": 35,
    "datacenter": 25,
    "i2p": 40,
}

NETWORK_KIND_LABELS = (
    ("is_loopback", "loopback", "Loopback address; external enrichment is skipped."),
    ("is_private", "private", "Private/internal address; external enrichment is skipped."),
    ("is_link_local", "link-local", "Link-local address; external enrichment is skipped."),
    ("is_multicast", "multicast", "Multicast address; external enrichment is skipped."),
    ("is_reserved", "reserved", "Reserved/special-use address; external enrichment is skipped."),
    ("is_unspecified", "unspecified", "Unspecified address; external enrichment is skipped."),
)


class LookupService:
    def __init__(
        self,
        cache: TTLCache[str, Dict[str, Any]],
        history: HistoryService,
        stats: RuntimeStatsTracker,
        providers: ExternalProviders,
    ) -> None:
        self._cache = cache
        self._history = history
        self._stats = stats
        self._providers = providers

    def _now(self) -> int:
        return int(time.time())

    async def _rdap_lookup(self, ip: str) -> Dict[str, Any]:
        data = await asyncio.to_thread(rdap_enrich, ip)
        return data or {}

    async def _reverse_dns(self, ip: str) -> Dict[str, Any]:
        ptr = await asyncio.to_thread(reverse_dns, ip)
        return {"reverse_dns": ptr} if ptr else {}

    @staticmethod
    def _ip_classification(ip: str | None) -> Dict[str, Any]:
        if not ip:
            return {"ip_version": None, "ip_kind": None, "is_public": None, "network_notes": []}
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return {"ip_version": None, "ip_kind": "invalid", "is_public": False, "network_notes": ["Invalid IP address."]}

        notes: list[str] = []
        kind = "public"
        for attr, label, note in NETWORK_KIND_LABELS:
            if getattr(ip_obj, attr):
                kind = label
                notes.append(note)
                break

        if ip_obj.version == 6 and ip_obj.ipv4_mapped:
            notes.append(f"IPv4-mapped IPv6 address for {ip_obj.ipv4_mapped}.")
        if ip_obj.is_global:
            kind = "public"

        return {
            "ip_version": ip_obj.version,
            "ip_kind": kind,
            "is_public": bool(ip_obj.is_global),
            "network_notes": notes,
        }

    @classmethod
    def _is_public_ip(cls, ip: str) -> bool:
        return bool(cls._ip_classification(ip).get("is_public"))

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        out: list[str] = []
        for value in values:
            item = (value or "").strip()
            if item and item not in out:
                out.append(item)
        return out


    @staticmethod
    def _extract_asn_number(*values: Any) -> int | None:
        for value in values:
            if value is None:
                continue
            match = re.search(r"\bAS\s*(\d{1,10})\b", str(value), flags=re.IGNORECASE)
            if match:
                return int(match.group(1))
        return None

    @staticmethod
    def _risk_from_security(security: Dict[str, Any]) -> Dict[str, Any]:
        signals: list[str] = []
        score = 0
        for key, weight in RISK_WEIGHTS.items():
            if security.get(key):
                score += weight
                signals.append(key)
        score = min(score, 100)
        if score >= 70:
            level = "high"
        elif score >= 35:
            level = "medium"
        else:
            level = "low"
        return {"risk_score": float(score), "risk_level": level, "risk_signals": signals}

    async def _resolve_ip_core(self, ip: str) -> Dict[str, Any]:
        cache_key = f"ip:{ip}"
        cached = self._cache.get(cache_key)
        if cached:
            return {"cached": True, **cached}

        classification = self._ip_classification(ip)
        details = geoip_lookup(ip) or {"ip": ip, "source": "local"}
        details.update(classification)
        details["security"] = security_flags(ip)
        details.update(self._risk_from_security(details["security"]))

        if not details.get("country_name") and classification.get("is_public"):
            external = await self._providers.online_fallback(ip)
            if external:
                for key, value in external.items():
                    if details.get(key) in (None, "", [], {}):
                        details[key] = value
                base_source = details.get("source") or "local"
                details["source"] = f"{base_source}+ext"

        if classification.get("is_public"):
            rdap_details = await self._rdap_lookup(ip)
            if rdap_details:
                details.update(rdap_details)

            asn_number = self._extract_asn_number(details.get("rdap_asn"), details.get("org"))
            if asn_number:
                details["asn"] = asn_number
                try:
                    details["asn_info"] = await self._providers.asn_profile(asn_number)
                except Exception:
                    details.setdefault("asn_info", None)

            ptr_details = await self._reverse_dns(ip)
            if ptr_details:
                details.update(ptr_details)
        else:
            details.setdefault("rdap_source", None)
            details.setdefault("reverse_dns", None)
            details.setdefault("asn_info", None)

        self._cache.set(cache_key, details)
        return {"cached": False, **details}

    @staticmethod
    def _confidence_label(score: int) -> str:
        if score >= 75:
            return "high"
        if score >= 45:
            return "medium"
        return "low"

    def _provider_from_text(self, *values: str | None) -> str | None:
        text = " ".join(value or "" for value in values).lower()
        for needle, provider in CDN_PROVIDER_HINTS.items():
            if needle in text:
                return provider
        return None

    def _provider_from_nameservers(self, nameservers: list[str]) -> str | None:
        text = " ".join(nameservers).lower()
        for needle, provider in NS_PROVIDER_HINTS.items():
            if needle in text:
                return provider
        return None

    def _provider_from_candidate(self, candidate: Dict[str, Any], ip_data: Dict[str, Any]) -> str | None:
        return self._provider_from_text(
            ip_data.get("org"),
            ip_data.get("rdap_org"),
            ip_data.get("rdap_name"),
            ip_data.get("reverse_dns"),
            ", ".join(candidate.get("resolved_ips") or []),
            ", ".join((candidate.get("dns") or {}).get("cname") or []),
        )

    def _candidate_confidence(
        self,
        candidate: Dict[str, Any],
        *,
        provider: str | None,
        same_as_edge: bool,
        has_resolved_ips: bool,
        routing: Dict[str, Any] | None,
    ) -> int:
        score = int(candidate.get("confidence") or 0)
        sources = set(candidate.get("sources") or [])

        if "mx" in sources:
            score -= 14
        if "ct" in sources:
            score += 6
        if "js" in sources:
            score += 8
        if "html" in sources or "csp" in sources:
            score += 4
        if has_resolved_ips and not same_as_edge:
            score += 10
        if has_resolved_ips and not provider and not same_as_edge:
            score += 12
        if same_as_edge:
            score -= 12
        if not has_resolved_ips:
            score -= 8
        if routing and routing.get("provider") and provider == routing.get("provider"):
            score -= 5

        return max(5, min(score, 99))

    def _domain_routing(self, dns_profile: Dict[str, list[str]], ip_data: Dict[str, Any]) -> Dict[str, Any] | None:
        notes: list[str] = []
        provider: str | None = None
        is_proxied = False

        nameservers = dns_profile.get("ns") or []
        ns_provider = self._provider_from_nameservers(nameservers)
        if ns_provider:
            provider = ns_provider
            notes.append(f"Authoritative nameservers suggest {ns_provider} infrastructure.")
            if ns_provider in {"Cloudflare", "Akamai", "Fastly", "Vercel", "Netlify", "Bunny"}:
                is_proxied = True

        cname_provider = self._provider_from_text(", ".join(dns_profile.get("cname") or []))
        if cname_provider:
            provider = provider or cname_provider
            notes.append(f"CNAME chain points to {cname_provider} edge infrastructure.")
            is_proxied = True

        edge_provider = self._provider_from_text(
            ip_data.get("org"),
            ip_data.get("rdap_org"),
            ip_data.get("rdap_name"),
            ip_data.get("reverse_dns"),
        )
        if edge_provider:
            provider = provider or edge_provider
            notes.append(f"The selected visible IP appears to belong to {edge_provider} edge infrastructure.")

        is_cdn = provider is not None
        is_origin_hidden = bool(is_cdn and (is_proxied or dns_profile.get("cname") or ip_data.get("ip")))
        if is_origin_hidden:
            notes.append("The visible A/AAAA records look like edge or reverse-proxy IPs, not necessarily the origin server.")

        if not notes and not provider:
            return None

        return {
            "provider": provider,
            "is_cdn": is_cdn,
            "is_proxied": is_proxied,
            "is_origin_hidden": is_origin_hidden,
            "notes": notes,
        }

    async def _origin_candidates(
        self,
        domain: str,
        dns_profile: Dict[str, list[str]],
        edge_ips: list[str],
        routing: Dict[str, Any] | None,
    ) -> list[Dict[str, Any]]:
        raw_candidates = await self._providers.discover_origin_candidates(domain, dns_profile)
        edge_ip_set = set(edge_ips)
        output: list[Dict[str, Any]] = []

        for raw in raw_candidates:
            candidate_ips = self._dedupe(raw.get("resolved_ips") or [])
            same_as_edge = bool(candidate_ips) and set(candidate_ips).issubset(edge_ip_set)
            sources = set(raw.get("sources") or [])

            if sources and sources.issubset({"heuristic", "wordlist"}) and (not candidate_ips or same_as_edge):
                continue

            selected_ip = next((ip for ip in candidate_ips if ":" not in ip), None)
            if not selected_ip and candidate_ips:
                selected_ip = candidate_ips[0]

            ip_data: Dict[str, Any] = {}
            if selected_ip:
                ip_data = await self._resolve_ip_core(selected_ip)

            provider = self._provider_from_candidate(raw, ip_data)
            is_cdn = provider is not None
            notes: list[str] = []

            if raw.get("source") == "mx":
                notes.append("Derived from an MX target; this may be mail infrastructure rather than the web origin.")
            elif raw.get("source") == "ct":
                notes.append("Observed in certificate transparency logs.")
            elif raw.get("source") == "js":
                notes.append("Referenced by a same-domain JavaScript asset.")
            elif raw.get("source") in {"html", "csp", "txt"}:
                notes.append("Referenced by same-domain application metadata or page content.")
            else:
                notes.append("Resolved via a common origin-hostname heuristic.")

            if same_as_edge:
                notes.append("This candidate resolves to the same visible edge IPs as the apex domain.")
            elif not candidate_ips:
                notes.append("This candidate is referenced by discovery sources but does not currently resolve.")

            if routing and routing.get("provider") and provider == routing.get("provider"):
                notes.append(f"This candidate still appears to sit on {routing.get('provider')} infrastructure.")
            elif candidate_ips and not same_as_edge:
                notes.append("This candidate does not match the visible apex edge IPs.")

            confidence = self._candidate_confidence(
                raw,
                provider=provider,
                same_as_edge=same_as_edge,
                has_resolved_ips=bool(candidate_ips),
                routing=routing,
            )

            output.append(
                {
                    "hostname": raw.get("hostname"),
                    "source": raw.get("source"),
                    "sources": raw.get("sources") or [],
                    "matched_rule": raw.get("matched_rule"),
                    "resolved_ips": candidate_ips,
                    "selected_ip": selected_ip,
                    "provider": provider,
                    "is_cdn": is_cdn,
                    "same_as_edge": same_as_edge,
                    "confidence": confidence,
                    "confidence_label": self._confidence_label(confidence),
                    "evidence": raw.get("evidence") or [],
                    "notes": notes,
                }
            )
        output.sort(key=lambda item: (-int(item.get("confidence") or 0), str(item.get("hostname") or "")))
        return output

    async def resolve_target(self, target: LookupTarget) -> Dict[str, Any]:
        started = time.perf_counter()
        if target.query_type == "domain" and target.domain:
            payload = await self._resolve_domain_target(target)
        elif target.query_type == "asn" and target.asn is not None:
            payload = await self._resolve_asn_target(target)
        elif target.query_type == "prefix" and target.prefix:
            payload = await self._resolve_prefix_target(target)
        else:
            if not target.ip:
                raise ValueError("IP target is missing an IP address")
            payload = await self._resolve_ip_target(target)

        payload["response_time_ms"] = int((time.perf_counter() - started) * 1000)
        await self._record(payload)
        return LookupResponse(**payload).model_dump()

    async def _resolve_ip_target(self, target: LookupTarget) -> Dict[str, Any]:
        details = await self._resolve_ip_core(target.ip or "")
        return {
            "query": target.query,
            "query_type": target.query_type,
            "domain": target.domain,
            "asn": None,
            "prefix": target.prefix,
            "resolved_ips": [target.ip] if target.ip else [],
            "dns": None,
            "routing": None,
            "origin_candidates": [],
            **details,
        }

    async def _resolve_prefix_target(self, target: LookupTarget) -> Dict[str, Any]:
        details = await self._resolve_ip_core(target.ip or "")
        notes = list(details.get("network_notes") or [])
        notes.append("Prefix lookup uses the network address as the representative IP for enrichment.")
        details["network_notes"] = self._dedupe(notes)
        return {
            "query": target.query,
            "query_type": "prefix",
            "domain": None,
            "asn": None,
            "prefix": target.prefix,
            "resolved_ips": [target.ip] if target.ip else [],
            "dns": None,
            "routing": None,
            "origin_candidates": [],
            **details,
        }

    async def _resolve_asn_target(self, target: LookupTarget) -> Dict[str, Any]:
        cache_key = f"asn:{target.asn}"
        cached = self._cache.get(cache_key)
        if cached:
            return {"cached": True, **cached}

        asn_info = await self._providers.asn_profile(int(target.asn or 0))
        payload = {
            "query": target.query,
            "query_type": "asn",
            "domain": None,
            "asn": target.asn,
            "asn_info": asn_info,
            "prefix": None,
            "cached": False,
            "ip": None,
            "resolved_ips": [],
            "country_code": asn_info.get("country_code"),
            "country_name": None,
            "org": asn_info.get("holder") or asn_info.get("name"),
            "security": SecurityFlags().model_dump(),
            "risk_score": 0,
            "risk_level": "low",
            "risk_signals": [],
            "dns": None,
            "routing": None,
            "origin_candidates": [],
            "source": asn_info.get("source") or "ripe-stat",
        }
        self._cache.set(cache_key, payload)
        return payload

    async def _resolve_domain_target(self, target: LookupTarget) -> Dict[str, Any]:
        cache_key = f"domain:{target.domain}"
        cached = self._cache.get(cache_key)
        if cached:
            return {"cached": True, **cached}

        dns_profile = await self._providers.domain_dns_profile(target.domain or "")
        has_dns_data = any(dns_profile.values())
        resolved_ips = self._dedupe((dns_profile.get("a") or []) + (dns_profile.get("aaaa") or []))

        selected_ip = next((ip for ip in resolved_ips if ":" not in ip), None)
        if not selected_ip and resolved_ips:
            selected_ip = resolved_ips[0]
        if not selected_ip and target.domain:
            selected_ip = await resolve_domain_to_ip(target.domain)
            if selected_ip:
                resolved_ips = self._dedupe(resolved_ips + [selected_ip])
        if not selected_ip and not has_dns_data:
            raise LookupError("Domain did not resolve to any DNS records")

        ip_data: Dict[str, Any] = {
            "cached": False,
            "ip": selected_ip,
            "security": SecurityFlags().model_dump(),
            "risk_score": 0,
            "risk_level": "low",
            "risk_signals": [],
            "source": "domain-dns",
        }
        if selected_ip:
            ip_data = await self._resolve_ip_core(selected_ip)

        routing = self._domain_routing(dns_profile, ip_data)
        origin_candidates: list[Dict[str, Any]] = []
        if routing and routing.get("is_origin_hidden"):
            origin_candidates = await self._origin_candidates(target.domain or "", dns_profile, resolved_ips, routing)

        source = ip_data.get("source") or "domain-dns"
        if dns_profile:
            source = f"{source}+domain-dns" if "domain-dns" not in source else source

        payload = {
            "query": target.query,
            "query_type": target.query_type,
            "domain": target.domain,
            "asn": None,
            "prefix": None,
            "resolved_ips": resolved_ips,
            "dns": dns_profile,
            "routing": routing,
            "origin_candidates": origin_candidates,
            **ip_data,
            "source": source,
        }
        domain_cache_payload = dict(payload)
        domain_cache_payload["cached"] = False
        self._cache.set(cache_key, domain_cache_payload)
        return payload

    async def _record(self, payload: Dict[str, Any]) -> None:
        payload.setdefault("ts", self._now())
        await self._history.save(payload)
        self._stats.bump(payload)
