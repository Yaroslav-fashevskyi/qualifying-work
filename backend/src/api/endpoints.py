from __future__ import annotations

from typing import List
import io
import csv

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from ..models import (
    LookupResponse,
    HistoryRecord,
    StatsResponse,
    RuntimeStats,
    HealthResponse,
    MeResponse,
    BatchLookupRequest,
    BatchLookupItem,
    BatchLookupResponse,
    CacheStatsResponse,
)
from ..utils.ip_utils import client_ip, parse_query_target
from ..services import (
    LookupService,
    HistoryService,
    RuntimeStatsTracker,
    SlidingWindowRateLimiter,
)
from ..services.cache import TTLCache
from ..services.rate_limiter import RateLimitExceeded
from ..utils.local_geoip import CITY_DB, ASN_DB


router = APIRouter(prefix="/api", tags=["Lookup"])

_lookup_service: LookupService | None = None
_history_service: HistoryService | None = None
_stats_tracker: RuntimeStatsTracker | None = None
_rate_limiter: SlidingWindowRateLimiter | None = None
_cache: TTLCache[str, dict] | None = None
_db_path: str | None = None


def configure(
    lookup: LookupService,
    history: HistoryService,
    stats_tracker: RuntimeStatsTracker,
    rate_limiter: SlidingWindowRateLimiter,
    db_path: str,
    cache: TTLCache[str, dict] | None = None,
) -> None:
    global _lookup_service, _history_service, _stats_tracker, _rate_limiter, _db_path, _cache
    _lookup_service = lookup
    _history_service = history
    _stats_tracker = stats_tracker
    _rate_limiter = rate_limiter
    _db_path = db_path
    _cache = cache


def _lookup_dep() -> LookupService:
    if _lookup_service is None:
        raise RuntimeError("Lookup service is not configured")
    return _lookup_service


def _history_dep() -> HistoryService:
    if _history_service is None:
        raise RuntimeError("History service is not configured")
    return _history_service


def _stats_dep() -> RuntimeStatsTracker:
    if _stats_tracker is None:
        raise RuntimeError("Stats tracker is not configured")
    return _stats_tracker


def _rate_dep() -> SlidingWindowRateLimiter:
    if _rate_limiter is None:
        raise RuntimeError("Rate limiter is not configured")
    return _rate_limiter


def _cache_dep() -> TTLCache[str, dict]:
    if _cache is None:
        raise RuntimeError("Cache is not configured")
    return _cache


async def _resolve_or_http_error(service: LookupService, q: str) -> LookupResponse:
    target = await parse_query_target(q)
    if not target:
        raise HTTPException(status_code=400, detail="Invalid IP, prefix, ASN or domain")
    try:
        result = await service.resolve_target(target)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return LookupResponse(**result)


@router.get("/me", response_model=MeResponse, summary="Detect caller IP address")
async def me(request: Request) -> MeResponse:
    return MeResponse(ip=client_ip(request))


@router.get(
    "/lookup",
    response_model=LookupResponse,
    summary="Resolve geolocation, ASN, DNS and security details for an IP, prefix, ASN or domain",
    responses={
        200: {"description": "Lookup completed successfully."},
        400: {"description": "Invalid IP address, prefix, ASN or domain."},
        429: {"description": "Rate limit exceeded."},
    },
)
async def lookup(
    request: Request,
    q: str = Query(
        ...,
        description=(
            "IP address, CIDR prefix, ASN or domain name to resolve. Domain queries return selected edge-IP enrichment and DNS context."
        ),
        examples=[
            {"summary": "IPv4 address", "value": "8.8.8.8"},
            {"summary": "IPv6 address", "value": "2001:4860:4860::8888"},
            {"summary": "CIDR prefix", "value": "1.1.1.0/24"},
            {"summary": "ASN", "value": "AS15169"},
            {"summary": "Hostname", "value": "example.com"},
        ],
    ),
    limiter: SlidingWindowRateLimiter = Depends(_rate_dep),
    service: LookupService = Depends(_lookup_dep),
) -> LookupResponse:
    try:
        limiter.check(client_ip(request))
    except RateLimitExceeded:
        raise HTTPException(status_code=429, detail="Too many requests") from None
    return await _resolve_or_http_error(service, q)


@router.post(
    "/lookup/batch",
    response_model=BatchLookupResponse,
    summary="Resolve up to 25 IP/domain/ASN targets in one request",
)
async def batch_lookup(
    request: Request,
    payload: BatchLookupRequest,
    limiter: SlidingWindowRateLimiter = Depends(_rate_dep),
    service: LookupService = Depends(_lookup_dep),
) -> BatchLookupResponse:
    try:
        limiter.check(client_ip(request), hits=max(1, len(payload.queries)))
    except RateLimitExceeded:
        raise HTTPException(status_code=429, detail="Too many requests") from None

    items: list[BatchLookupItem] = []
    for raw_query in payload.queries:
        query = (raw_query or "").strip()
        if not query:
            continue
        try:
            result = await _resolve_or_http_error(service, query)
            items.append(BatchLookupItem(query=query, ok=True, result=result))
        except HTTPException as exc:
            items.append(BatchLookupItem(query=query, ok=False, error=str(exc.detail)))
        except Exception as exc:
            items.append(BatchLookupItem(query=query, ok=False, error=str(exc)))

    ok_count = sum(1 for item in items if item.ok)
    return BatchLookupResponse(total=len(items), ok=ok_count, failed=len(items) - ok_count, items=items)


@router.get("/history", response_model=List[HistoryRecord], summary="Return recent lookup history entries")
async def history(
    limit: int = Query(50, ge=1, le=500, description="Number of recent records to return."),
    query: str | None = Query(None, description="Optional search over query, IP, domain or organization."),
    query_type: str | None = Query(None, pattern="^(ip|domain|asn|prefix)$", description="Optional query type filter."),
    flagged: bool | None = Query(None, description="Filter only records with/without security flags."),
    history_service: HistoryService = Depends(_history_dep),
) -> List[HistoryRecord]:
    rows = await history_service.recent(limit, query=query, query_type=query_type, flagged=flagged)
    return [HistoryRecord.from_row(row) for row in rows]


@router.delete("/history", summary="Clear stored lookup history", response_description="Confirmation JSON object")
async def clear_history(history_service: HistoryService = Depends(_history_dep)):
    await history_service.clear()
    return {"ok": True}


@router.get("/history/export", summary="Export lookup history as CSV", response_description="CSV stream containing the full lookup history")
async def history_export(history_service: HistoryService = Depends(_history_dep)):
    async def stream():
        buffer = io.StringIO()
        writer = None
        wrote_any = False
        async for row in history_service.export_rows():
            if writer is None:
                writer = csv.DictWriter(buffer, fieldnames=list(row.keys()))
                writer.writeheader()
                yield buffer.getvalue()
                buffer.seek(0)
                buffer.truncate(0)
            writer.writerow(row)
            wrote_any = True
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)
        if not wrote_any:
            yield "no data\n"

    headers = {"Content-Disposition": 'attachment; filename="history.csv"'}
    return StreamingResponse(stream(), media_type="text/csv", headers=headers)


@router.get("/stats", response_model=StatsResponse, summary="Return runtime counters and aggregated history stats")
async def stats(
    history_service: HistoryService = Depends(_history_dep),
    stats_tracker: RuntimeStatsTracker = Depends(_stats_dep),
) -> StatsResponse:
    runtime = stats_tracker.snapshot()
    aggregated_country = await history_service.aggregate_by_country()
    aggregated_type = await history_service.aggregate_by_query_type()
    security_hits = await history_service.aggregate_security_hits()
    cache_summary = await history_service.cache_summary()
    summary = await history_service.summary()
    return StatsResponse(
        runtime=RuntimeStats(**runtime),
        db_by_country=aggregated_country,
        db_by_query_type=aggregated_type,
        db_security_hits=security_hits,
        db_cache=cache_summary,
        total_history=summary["total_history"],
        latest_ts=summary["latest_ts"],
    )


@router.get("/cache", response_model=CacheStatsResponse, summary="Return in-memory cache diagnostics")
async def cache_stats(cache: TTLCache[str, dict] = Depends(_cache_dep)) -> CacheStatsResponse:
    return CacheStatsResponse(**cache.stats())


@router.delete("/cache", summary="Clear in-memory lookup cache")
async def clear_cache(cache: TTLCache[str, dict] = Depends(_cache_dep)):
    cache.clear()
    return {"ok": True}


@router.get("/health", response_model=HealthResponse, summary="Expose service health and dataset availability")
async def health() -> HealthResponse:
    if _db_path is None:
        raise RuntimeError("API router not configured with db_path")
    cache_payload = CacheStatsResponse(**_cache.stats()) if _cache is not None else None
    return HealthResponse(
        city_db=str(CITY_DB),
        city_db_exists=CITY_DB.exists(),
        asn_db=str(ASN_DB),
        asn_db_exists=ASN_DB.exists(),
        db_path=_db_path,
        cache=cache_payload,
    )
