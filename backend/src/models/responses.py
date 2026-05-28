from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class SecurityFlags(BaseModel):
    vpn: bool = False
    proxy: bool = False
    tor: bool = False
    i2p: bool = False
    datacenter: bool = False
    threat: bool = False


class DomainDnsRecords(BaseModel):
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    caa: list[str] = Field(default_factory=list)
    soa: list[str] = Field(default_factory=list)


class DomainRouting(BaseModel):
    provider: Optional[str] = None
    is_cdn: bool = False
    is_proxied: bool = False
    is_origin_hidden: bool = False
    notes: list[str] = Field(default_factory=list)


class OriginCandidate(BaseModel):
    hostname: str
    source: str
    sources: list[str] = Field(default_factory=list)
    matched_rule: Optional[str] = None
    resolved_ips: list[str] = Field(default_factory=list)
    selected_ip: Optional[str] = None
    provider: Optional[str] = None
    is_cdn: bool = False
    same_as_edge: bool = False
    confidence: int = 0
    confidence_label: str = "low"
    evidence: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class AsnInfo(BaseModel):
    asn: int
    holder: Optional[str] = None
    name: Optional[str] = None
    country_code: Optional[str] = None
    registry: Optional[str] = None
    allocated: Optional[str] = None
    prefixes: list[str] = Field(default_factory=list)
    source: Optional[str] = None


class LookupResponse(BaseModel):
    model_config = ConfigDict(
        extra="ignore",
        json_schema_extra={
            "example": {
                "cached": False,
                "query": "example.com",
                "query_type": "domain",
                "domain": "example.com",
                "ip": "8.8.8.8",
                "resolved_ips": ["8.8.8.8"],
                "ip_version": 4,
                "ip_kind": "public",
                "is_public": True,
                "country_name": "United States",
                "country_code": "US",
                "region": "California",
                "city": "Mountain View",
                "timezone": "America/Los_Angeles",
                "latitude": 37.751,
                "longitude": -97.822,
                "org": "Google LLC",
                "rdap_org": "GOGL",
                "rdap_name": "Google LLC",
                "rdap_source": "rdap.arin.net",
                "rdap_handle": "NET-8-8-8-0-1",
                "rdap_range": "8.8.8.0/24",
                "rdap_type": "ALLOCATED PA",
                "rdap_asn": "AS15169",
                "rdap_registered": "2000-03-30T00:00:00Z",
                "rdap_abuse": "abuse@google.com",
                "reverse_dns": "dns.google",
                "security": {
                    "vpn": False,
                    "proxy": False,
                    "tor": False,
                    "i2p": False,
                    "datacenter": False,
                    "threat": False,
                },
                "risk_score": 0,
                "risk_level": "low",
                "risk_signals": [],
                "dns": {
                    "a": ["8.8.8.8"],
                    "aaaa": [],
                    "cname": [],
                    "mx": [],
                    "ns": ["ns1.example.com."],
                    "txt": [],
                    "caa": [],
                    "soa": [],
                },
                "routing": {
                    "provider": "Cloudflare",
                    "is_cdn": True,
                    "is_proxied": True,
                    "is_origin_hidden": True,
                    "notes": [
                        "Authoritative nameservers point to Cloudflare.",
                        "The visible A/AAAA records look like CDN edge IPs, not necessarily the origin server.",
                    ],
                },
                "origin_candidates": [],
                "response_time_ms": 118,
                "source": "local+ext",
            }
        },
    )

    query: str = Field(description="Original user query.")
    query_type: str = Field(description="Query type: ip, domain, asn or prefix.")
    domain: Optional[str] = Field(default=None, description="Normalized domain name when the query is a domain.")
    asn: Optional[int] = Field(default=None, description="Autonomous System Number when the query is an ASN.")
    asn_info: Optional[AsnInfo] = Field(default=None, description="ASN profile for ASN queries or enrichment.")
    prefix: Optional[str] = Field(default=None, description="CIDR prefix when the query is a prefix.")
    cached: bool = Field(description="Indicates whether the response was served from the in-memory cache.")
    ip: Optional[str] = Field(default=None, description="Resolved IP address for the query or selected edge IP.")
    resolved_ips: list[str] = Field(default_factory=list, description="All resolved A/AAAA values discovered for a domain query.")
    ip_version: Optional[int] = Field(default=None, description="IP version for selected IP: 4 or 6.")
    ip_kind: Optional[str] = Field(default=None, description="Classification such as public/private/loopback/reserved.")
    is_public: Optional[bool] = Field(default=None, description="True when selected IP is globally routable.")
    network_notes: list[str] = Field(default_factory=list, description="Human-readable notes about the selected IP/network.")
    country_name: Optional[str] = Field(default=None, description="Country name.")
    country_code: Optional[str] = Field(default=None, description="Country ISO code.")
    region: Optional[str] = Field(default=None, description="Region or state.")
    city: Optional[str] = Field(default=None, description="City name.")
    timezone: Optional[str] = Field(default=None, description="IANA timezone.")
    latitude: Optional[float] = Field(default=None, description="Latitude in decimal degrees.")
    longitude: Optional[float] = Field(default=None, description="Longitude in decimal degrees.")
    org: Optional[str] = Field(default=None, description="Organization or ISP.")
    rdap_org: Optional[str] = Field(default=None, description="Organization handle from RDAP.")
    rdap_name: Optional[str] = Field(default=None, description="Entity display name from RDAP.")
    rdap_source: Optional[str] = Field(default=None, description="RDAP registry hostname that served the record.")
    rdap_handle: Optional[str] = Field(default=None, description="Network handle returned by RDAP.")
    rdap_range: Optional[str] = Field(default=None, description="CIDR or IP range from the RDAP response.")
    rdap_type: Optional[str] = Field(default=None, description="Allocation type reported by RDAP.")
    rdap_asn: Optional[str] = Field(default=None, description="Origin ASN extracted from the RDAP record.")
    rdap_registered: Optional[str] = Field(default=None, description="Registration date of the RDAP record.")
    rdap_abuse: Optional[str] = Field(default=None, description="Abuse contact e-mail extracted from RDAP.")
    reverse_dns: Optional[str] = Field(default=None, description="PTR (reverse DNS) record, if resolved.")
    security: SecurityFlags = Field(default_factory=SecurityFlags, description="Security flags from local lists.")
    risk_score: float = Field(default=0, ge=0, le=100, description="Deterministic risk score calculated from security flags.")
    risk_level: str = Field(default="low", description="low, medium or high risk level.")
    risk_signals: list[str] = Field(default_factory=list, description="Readable risk signal labels.")
    dns: Optional[DomainDnsRecords] = Field(default=None, description="DNS records collected for domain queries.")
    routing: Optional[DomainRouting] = Field(default=None, description="Domain routing hints such as CDN or reverse-proxy detection.")
    origin_candidates: list[OriginCandidate] = Field(default_factory=list, description="Potential origin or infrastructure hostnames discovered for the domain.")
    response_time_ms: Optional[int] = Field(default=None, description="Backend processing time for this lookup.")
    source: Optional[str] = Field(default=None, description="Data source (local MMDB, online provider, combined, etc.).")


class HistoryRecord(BaseModel):
    id: int
    ts: int
    query: Optional[str] = None
    query_type: Optional[str] = None
    domain: Optional[str] = None
    asn: Optional[int] = None
    ip: Optional[str] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    org: Optional[str] = None
    source: Optional[str] = None
    cached: bool = False
    risk_score: float = 0
    risk_level: str = "low"
    response_time_ms: Optional[int] = None
    vpn: bool = False
    proxy: bool = False
    tor: bool = False
    i2p: bool = False
    datacenter: bool = False
    threat: bool = False

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "HistoryRecord":
        payload = dict(row)
        for key in ("cached", "vpn", "proxy", "tor", "i2p", "datacenter", "threat"):
            payload[key] = bool(payload.get(key))
        payload.setdefault("risk_score", 0)
        payload.setdefault("risk_level", "low")
        return cls(**payload)


class RuntimeStats(BaseModel):
    total_lookups: int
    cache_hits: int = 0
    cache_misses: int = 0
    cache_hit_ratio: float = 0
    avg_response_ms: float = 0
    by_country: Dict[str, int]
    by_query_type: Dict[str, int] = Field(default_factory=dict)
    security_hits: Dict[str, int] = Field(default_factory=dict)
    since: int


class StatsResponse(BaseModel):
    runtime: RuntimeStats
    db_by_country: Dict[str, int]
    db_by_query_type: Dict[str, int] = Field(default_factory=dict)
    db_security_hits: Dict[str, int] = Field(default_factory=dict)
    db_cache: Dict[str, int] = Field(default_factory=dict)
    total_history: int = 0
    latest_ts: Optional[int] = None


class BatchLookupRequest(BaseModel):
    queries: list[str] = Field(min_length=1, max_length=25, description="IP/domain/ASN targets to resolve.")


class BatchLookupItem(BaseModel):
    query: str
    ok: bool
    result: Optional[LookupResponse] = None
    error: Optional[str] = None


class BatchLookupResponse(BaseModel):
    total: int
    ok: int
    failed: int
    items: list[BatchLookupItem]


class CacheStatsResponse(BaseModel):
    ttl_seconds: float
    max_entries: int
    size: int
    hits: int
    misses: int
    hit_ratio: float


class HealthResponse(BaseModel):
    city_db: str
    city_db_exists: bool
    asn_db: str
    asn_db_exists: bool
    db_path: str
    cache: CacheStatsResponse | None = None


class MeResponse(BaseModel):
    ip: str
