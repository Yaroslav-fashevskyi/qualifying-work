export interface SecurityFlags {
  vpn: boolean
  proxy: boolean
  tor: boolean
  i2p: boolean
  datacenter: boolean
  threat: boolean
}

export interface DomainDnsRecords {
  a: string[]
  aaaa: string[]
  cname: string[]
  mx: string[]
  ns: string[]
  txt: string[]
  caa: string[]
  soa: string[]
}

export interface DomainRouting {
  provider: string | null
  is_cdn: boolean
  is_proxied: boolean
  is_origin_hidden: boolean
  notes: string[]
}

export interface OriginCandidate {
  hostname: string
  source: string
  sources: string[]
  matched_rule: string | null
  resolved_ips: string[]
  selected_ip: string | null
  provider: string | null
  is_cdn: boolean
  same_as_edge: boolean
  confidence: number
  confidence_label: string
  evidence: string[]
  notes: string[]
}

export interface LookupResponse {
  query: string
  query_type: string
  domain: string | null
  cached: boolean
  ip: string | null
  resolved_ips: string[]
  country_name: string | null
  country_code: string | null
  region: string | null
  city: string | null
  timezone: string | null
  latitude: number | null
  longitude: number | null
  org: string | null
  rdap_org: string | null
  rdap_name: string | null
  rdap_source?: string | null
  rdap_handle: string | null
  rdap_range: string | null
  rdap_type: string | null
  rdap_asn: string | null
  rdap_registered: string | null
  rdap_abuse: string | null
  reverse_dns: string | null
  security: SecurityFlags
  dns: DomainDnsRecords | null
  routing: DomainRouting | null
  origin_candidates: OriginCandidate[]
  source: string | null
}

export interface HistoryRecord {
  id: number
  ts: number
  query: string | null
  query_type: string | null
  ip: string
  country_code: string | null
  country_name: string | null
  city: string | null
  region: string | null
  org: string | null
  source: string | null
  cached: boolean
  vpn: boolean
  proxy: boolean
  tor: boolean
  i2p: boolean
  datacenter: boolean
  threat: boolean
}

export interface RuntimeStats {
  total_lookups: number
  by_country: Record<string, number>
  since: number
}

export interface StatsResponse {
  runtime: RuntimeStats
  db_by_country: Record<string, number>
}

export interface MeResponse {
  ip: string
}
