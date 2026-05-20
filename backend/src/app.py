import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware

from .api import endpoints as api_endpoints
from .services import (
    TTLCache,
    SlidingWindowRateLimiter,
    HistoryService,
    RuntimeStatsTracker,
    LookupService,
)
from .services.providers import ExternalProviders

APP_TITLE = "IP Intelligence Backend"
BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = BASE_DIR / "src" / "data" / "app.sqlite"
DB_PATH = os.getenv("APP_DB_PATH", str(DEFAULT_DB_PATH))


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


CACHE_TTL_SEC = _positive_int_env("CACHE_TTL_SEC", 600)
CACHE_MAX_ENTRIES = _positive_int_env("CACHE_MAX_ENTRIES", 5000)
RATE_LIMIT_WINDOW_SEC = _positive_int_env("RATE_LIMIT_WINDOW_SEC", 300)
RATE_LIMIT_MAX = _positive_int_env("RATE_LIMIT_MAX", 200)

Path(DB_PATH).expanduser().parent.mkdir(parents=True, exist_ok=True)


def _cors_allow_origins() -> list[str]:
    raw = os.getenv("CORS_ALLOW_ORIGINS", "*")
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    return origins or ["*"]


cache = TTLCache[str, dict](ttl_seconds=CACHE_TTL_SEC, max_entries=CACHE_MAX_ENTRIES)
history_service = HistoryService(DB_PATH)
stats_tracker = RuntimeStatsTracker()
providers = ExternalProviders()
lookup_service = LookupService(
    cache=cache,
    history=history_service,
    stats=stats_tracker,
    providers=providers,
)
rate_limiter = SlidingWindowRateLimiter(
    window_seconds=RATE_LIMIT_WINDOW_SEC, max_hits=RATE_LIMIT_MAX
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await history_service.init_db()
    yield


app = FastAPI(
    title=APP_TITLE,
    summary="Backend API for IP, domain and ASN enrichment.",
    lifespan=lifespan,
)
app.add_middleware(GZipMiddleware, minimum_size=500)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_allow_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)

api_endpoints.configure(
    lookup=lookup_service,
    history=history_service,
    stats_tracker=stats_tracker,
    rate_limiter=rate_limiter,
    db_path=DB_PATH,
    cache=cache,
)
app.include_router(api_endpoints.router)


@app.get("/", tags=["Meta"], summary="Describe the backend API")
async def root() -> dict[str, str]:
    return {
        "service": "ip-intelligence-backend",
        "docs_url": app.docs_url or "/docs",
        "health_url": "/api/health",
        "lookup_url": "/api/lookup?q=8.8.8.8",
    }
