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
                "origin_candidates": [
                    {
                        "hostname": "direct.example.com",
                        "source": "heuristic",
                        "sources": ["heuristic", "ct"],
                        "matched_rule": "direct",
                        "resolved_ips": ["203.0.113.10"],
                        "selected_ip": "203.0.113.10",
                        "provider": "Hetzner",
                        "is_cdn": False,
                        "same_as_edge": False,
                        "confidence": 82,
                        "confidence_label": "high",
                        "evidence": [
                            "Generated from the built-in `direct` hostname heuristic.",
                            "Observed in certificate transparency logs.",
                        ],
                        "notes": [
                            "Resolved via a common origin-hostname heuristic.",
                            "This candidate does not match the visible CDN edge IPs.",
                        ],
                    }
                ],
                "source": "local+ext",
            }
        },
    )

    query: str = Field(description="Original user query.")
    query_type: str = Field(description="Query type: ip or domain.")
    domain: Optional[str] = Field(
        default=None, description="Normalized domain name when the query is a domain."
    )
    cached: bool = Field(
        description="Indicates whether the response was served from the in-memory cache."
    )
    ip: Optional[str] = Field(
        default=None, description="Resolved IP address for the query or selected edge IP."
    )
    resolved_ips: list[str] = Field(
        default_factory=list,
        description="All resolved A/AAAA values discovered for a domain query.",
    )
    country_name: Optional[str] = Field(default=None, description="Country name.")
    country_code: Optional[str] = Field(default=None, description="Country ISO code.")
    region: Optional[str] = Field(default=None, description="Region or state.")
    city: Optional[str] = Field(default=None, description="City name.")
    timezone: Optional[str] = Field(default=None, description="IANA timezone.")
    latitude: Optional[float] = Field(
        default=None, description="Latitude in decimal degrees."
    )
    longitude: Optional[float] = Field(
        default=None, description="Longitude in decimal degrees."
    )
    org: Optional[str] = Field(default=None, description="Organization or ISP.")
    rdap_org: Optional[str] = Field(
        default=None, description="Organization handle from RDAP."
    )
    rdap_name: Optional[str] = Field(
        default=None, description="Entity display name from RDAP."
    )
    rdap_source: Optional[str] = Field(
        default=None, description="RDAP registry hostname that served the record."
    )
    rdap_handle: Optional[str] = Field(
        default=None, description="Network handle returned by RDAP."
    )
    rdap_range: Optional[str] = Field(
        default=None, description="CIDR or IP range from the RDAP response."
    )
    rdap_type: Optional[str] = Field(
        default=None, description="Allocation type reported by RDAP (e.g. ALLOCATED PA)."
    )
    rdap_asn: Optional[str] = Field(
        default=None, description="Origin ASN extracted from the RDAP record."
    )
    rdap_registered: Optional[str] = Field(
        default=None,
        description="Registration date of the RDAP record (ISO timestamp if available).",
    )
    rdap_abuse: Optional[str] = Field(
        default=None, description="Abuse contact e-mail extracted from RDAP."
    )
    reverse_dns: Optional[str] = Field(
        default=None, description="PTR (reverse DNS) record, if resolved."
    )
    security: SecurityFlags = Field(
        default_factory=SecurityFlags,
        description="Security flags describing whether the IP appears in VPN/proxy/TOR/I2P/datacenter/threat lists.",
    )
    dns: Optional[DomainDnsRecords] = Field(
        default=None,
        description="DNS records collected for domain queries.",
    )
    routing: Optional[DomainRouting] = Field(
        default=None,
        description="Domain routing hints such as CDN or reverse-proxy detection.",
    )
    origin_candidates: list[OriginCandidate] = Field(
        default_factory=list,
        description="Potential origin or infrastructure hostnames discovered for the domain.",
    )
    source: Optional[str] = Field(
        default=None,
        description="Data source (local MMDB, online provider, combined, etc.).",
    )


class HistoryRecord(BaseModel):
    id: int
    ts: int
    query: Optional[str] = None
    query_type: Optional[str] = None
    ip: str
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    org: Optional[str] = None
    source: Optional[str] = None
    cached: bool = False
    vpn: bool = False
    proxy: bool = False
    tor: bool = False
    i2p: bool = False
    datacenter: bool = False
    threat: bool = False

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "HistoryRecord":
        payload = dict(row)
        payload["cached"] = bool(payload.get("cached"))
        payload["vpn"] = bool(payload.get("vpn"))
        payload["proxy"] = bool(payload.get("proxy"))
        payload["tor"] = bool(payload.get("tor"))
        payload["i2p"] = bool(payload.get("i2p"))
        payload["datacenter"] = bool(payload.get("datacenter"))
        payload["threat"] = bool(payload.get("threat"))
        return cls(**payload)


class RuntimeStats(BaseModel):
    total_lookups: int
    by_country: Dict[str, int]
    since: int


class StatsResponse(BaseModel):
    runtime: RuntimeStats
    db_by_country: Dict[str, int]


class HealthResponse(BaseModel):
    city_db: str
    city_db_exists: bool
    asn_db: str
    asn_db_exists: bool
    db_path: str


class MeResponse(BaseModel):
    ip: str
