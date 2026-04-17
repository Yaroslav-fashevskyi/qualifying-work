from __future__ import annotations

from typing import Dict, Any
import asyncio
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
    "fastly": "Fastly",
    "akamai": "Akamai",
    "imperva": "Imperva",
    "incapsula": "Imperva",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "bunny": "Bunny",
}


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
        """Run the blocking RDAP lookup in a thread to avoid blocking the event loop."""
        data = await asyncio.to_thread(rdap_enrich, ip)
        return data or {}

    async def _reverse_dns(self, ip: str) -> Dict[str, Any]:
        ptr = await asyncio.to_thread(reverse_dns, ip)
        return {"reverse_dns": ptr} if ptr else {}

    async def _resolve_ip_core(self, ip: str) -> Dict[str, Any]:
        cached = self._cache.get(ip)
        if cached:
            return {"cached": True, **cached}

        details = geoip_lookup(ip) or {"ip": ip, "source": "local"}
        details["security"] = security_flags(ip)

        if not details.get("country_name"):
            external = await self._providers.online_fallback(ip)
            if external:
                for key, value in external.items():
                    if details.get(key) in (None, "", [], {}):
                        details[key] = value
                base_source = details.get("source") or "local"
                details["source"] = f"{base_source}+ext"

        rdap_details = await self._rdap_lookup(ip)
        if rdap_details:
            details.update(rdap_details)

        ptr_details = await self._reverse_dns(ip)
        if ptr_details:
            details.update(ptr_details)

        self._cache.set(ip, details)
        return {"cached": False, **details}

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        out: list[str] = []
        for value in values:
            item = (value or "").strip()
            if item and item not in out:
                out.append(item)
        return out

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

    def _provider_from_candidate(
        self, candidate: Dict[str, Any], ip_data: Dict[str, Any]
    ) -> str | None:
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
        if any(ns.endswith(".ns.cloudflare.com.") for ns in nameservers):
            provider = "Cloudflare"
            is_proxied = True
            notes.append("Authoritative nameservers point to Cloudflare.")

        edge_provider = self._provider_from_text(
            ip_data.get("org"),
            ip_data.get("rdap_org"),
            ip_data.get("rdap_name"),
            ip_data.get("reverse_dns"),
        )
        if edge_provider:
            provider = provider or edge_provider
            notes.append(
                f"The selected visible IP appears to belong to {edge_provider} edge infrastructure."
            )

        is_cdn = provider is not None
        is_origin_hidden = bool(is_cdn and (is_proxied or dns_profile.get("cname") or ip_data.get("ip")))
        if is_origin_hidden:
            notes.append(
                "The visible A/AAAA records look like edge or reverse-proxy IPs, not necessarily the origin server."
            )

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
        raw_candidates = await self._providers.discover_origin_candidates(
            domain, dns_profile
        )
        edge_ip_set = set(edge_ips)
        output: list[Dict[str, Any]] = []

        for raw in raw_candidates:
            candidate_ips = self._dedupe(raw.get("resolved_ips") or [])
            same_as_edge = bool(candidate_ips) and set(candidate_ips).issubset(edge_ip_set)
            sources = set(raw.get("sources") or [])

            if sources and sources.issubset({"heuristic", "wordlist"}) and (
                not candidate_ips or same_as_edge
            ):
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
                notes.append(
                    "Derived from an MX target; this may be mail infrastructure rather than the web origin."
                )
            elif raw.get("source") == "ct":
                notes.append("Observed in certificate transparency logs.")
            elif raw.get("source") == "js":
                notes.append("Referenced by a same-domain JavaScript asset.")
            elif raw.get("source") in {"html", "csp", "txt"}:
                notes.append("Referenced by same-domain application metadata or page content.")
            else:
                notes.append("Resolved via a common origin-hostname heuristic.")

            if same_as_edge:
                notes.append(
                    "This candidate resolves to the same visible edge IPs as the apex domain."
                )
            elif not candidate_ips:
                notes.append("This candidate is referenced by discovery sources but does not currently resolve.")

            if routing and routing.get("provider") and provider == routing.get("provider"):
                notes.append(
                    f"This candidate still appears to sit on {routing.get('provider')} infrastructure."
                )
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
        if target.query_type == "domain" and target.domain:
            return await self._resolve_domain_target(target)
        if not target.ip:
            raise ValueError("IP target is missing an IP address")
        return await self._resolve_ip_target(target)

    async def _resolve_ip_target(self, target: LookupTarget) -> Dict[str, Any]:
        details = await self._resolve_ip_core(target.ip or "")
        payload = {
            "query": target.query,
            "query_type": target.query_type,
            "domain": target.domain,
            "resolved_ips": [target.ip] if target.ip else [],
            "dns": None,
            "routing": None,
            "origin_candidates": [],
            **details,
        }
        await self._record(payload)
        return LookupResponse(**payload).model_dump()

    async def _resolve_domain_target(self, target: LookupTarget) -> Dict[str, Any]:
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
            "source": "domain-dns",
        }
        if selected_ip:
            ip_data = await self._resolve_ip_core(selected_ip)

        routing = self._domain_routing(dns_profile, ip_data)
        origin_candidates: list[Dict[str, Any]] = []
        if routing and routing.get("is_origin_hidden"):
            origin_candidates = await self._origin_candidates(
                target.domain or "",
                dns_profile,
                resolved_ips,
                routing,
            )
        source = ip_data.get("source") or "domain-dns"
        if dns_profile:
            source = f"{source}+domain-dns" if "domain-dns" not in source else source

        payload = {
            "query": target.query,
            "query_type": target.query_type,
            "domain": target.domain,
            "resolved_ips": resolved_ips,
            "dns": dns_profile,
            "routing": routing,
            "origin_candidates": origin_candidates,
            **ip_data,
            "source": source,
        }
        await self._record(payload)
        return LookupResponse(**payload).model_dump()

    async def _record(self, payload: Dict[str, Any]) -> None:
        payload.setdefault("ts", self._now())
        await self._history.save(payload)
        self._stats.bump(payload)
