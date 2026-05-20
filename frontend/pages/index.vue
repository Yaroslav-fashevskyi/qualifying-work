<script setup lang="ts">
import type { HistoryRecord, LookupResponse, MeResponse } from "~/types/api"

const route = useRoute()
const router = useRouter()
const { backendFetch } = useBackendApi()

const query = ref(typeof route.query.q === "string" ? route.query.q : "")
const result = ref<LookupResponse | null>(null)
const historyItems = ref<HistoryRecord[]>([])
const historySearch = ref("")
const progress = ref("Ready for lookup.")
const loading = ref(false)
const errorMessage = ref("")
const rawVisible = ref(false)

const numberFormatter = new Intl.NumberFormat("en-US")

const valueOr = (value: unknown, fallback = "n/a") => {
  if (value === null || value === undefined || value === "") {
    return fallback
  }
  return String(value)
}

const listOr = (items: string[] | null | undefined, limit = 12) => {
  const values = (items || []).filter(Boolean)
  if (!values.length) {
    return "n/a"
  }
  const visible = values.slice(0, limit).join(", ")
  const hidden = values.length - limit
  return hidden > 0 ? `${visible} +${hidden} more` : visible
}

const formatAsn = (asn?: number | null) => (asn ? `AS${asn}` : "n/a")

const formatDateTime = (ts?: number | null) => {
  return ts ? new Date(ts * 1000).toLocaleString() : "n/a"
}

const activeAsn = computed(() => result.value?.asn_info || null)
const activeAsnNumber = computed(() => activeAsn.value?.asn || result.value?.asn || null)

const ownerLabel = computed(() => {
  const item = result.value
  if (!item) {
    return "n/a"
  }
  return item.asn_info?.holder || item.asn_info?.name || item.org || item.rdap_name || item.rdap_org || "n/a"
})

const locationLabel = computed(() => {
  const item = result.value
  if (!item) {
    return "n/a"
  }
  const parts = [item.city, item.region, item.country_name || item.country_code].filter(Boolean)
  return parts.length ? parts.join(", ") : "n/a"
})

const resultTitle = computed(() => {
  const item = result.value
  if (!item) {
    return "No active result"
  }
  if (item.query_type === "asn") {
    return `${formatAsn(activeAsnNumber.value)} ${activeAsn.value?.holder || activeAsn.value?.name || ""}`.trim()
  }
  if (item.query_type === "domain") {
    return item.domain || item.query
  }
  return item.ip || item.prefix || item.query
})

const resultSubtitle = computed(() => {
  const item = result.value
  if (!item) {
    return "Run a lookup to populate geo, RDAP, DNS, ASN and security signals."
  }
  const parts = [
    item.query_type.toUpperCase(),
    activeAsnNumber.value ? formatAsn(activeAsnNumber.value) : null,
    ownerLabel.value !== "n/a" ? ownerLabel.value : null,
    item.source
  ].filter(Boolean)
  return parts.join(" · ")
})

const riskTone = computed(() => {
  const level = result.value?.risk_level
  if (level === "high") {
    return "danger"
  }
  if (level === "medium") {
    return "warning"
  }
  return "clean"
})

const summaryCards = computed(() => {
  const item = result.value
  if (!item) {
    return []
  }

  return [
    {
      label: "Target",
      value: item.query,
      detail: item.query_type.toUpperCase(),
      tone: "info"
    },
    {
      label: "Network",
      value: activeAsnNumber.value ? formatAsn(activeAsnNumber.value) : item.prefix || item.rdap_range || item.ip_kind || "n/a",
      detail: ownerLabel.value,
      tone: "accent"
    },
    {
      label: "Location",
      value: locationLabel.value,
      detail: item.timezone || "timezone n/a",
      tone: "info"
    },
    {
      label: "Risk",
      value: `${item.risk_level} · ${item.risk_score}/100`,
      detail: item.risk_signals.length ? item.risk_signals.join(", ") : "no local risk flags",
      tone: riskTone.value
    },
    {
      label: "Performance",
      value: item.response_time_ms != null ? `${item.response_time_ms} ms` : "n/a",
      detail: item.cached ? "cache hit" : "fresh/cache miss",
      tone: item.cached ? "clean" : "warning"
    }
  ]
})

const identityRows = computed(() => {
  const item = result.value
  if (!item) {
    return []
  }

  return [
    ["Query", item.query],
    ["Query type", item.query_type],
    ["Domain", item.domain || "n/a"],
    ["Selected IP", item.ip || "n/a"],
    ["Prefix / range", item.prefix || item.rdap_range || "n/a"],
    ["ASN", activeAsnNumber.value ? formatAsn(activeAsnNumber.value) : item.rdap_asn || "n/a"],
    ["IP version", item.ip_version ? `IPv${item.ip_version}` : "n/a"],
    ["IP kind", item.ip_kind || "n/a"],
    ["Public routable", item.is_public === null || item.is_public === undefined ? "n/a" : item.is_public ? "yes" : "no"],
    ["Resolved IPs", listOr(item.resolved_ips, 8)],
    ["Location", locationLabel.value],
    ["Coordinates", item.latitude != null && item.longitude != null ? `${item.latitude}, ${item.longitude}` : "n/a"],
    ["Organization", ownerLabel.value],
    ["Reverse DNS", item.reverse_dns || "n/a"],
    ["Source", item.source || activeAsn.value?.source || "n/a"]
  ]
})

const registryRows = computed(() => {
  const item = result.value
  if (!item) {
    return []
  }

  return [
    ["RDAP name", item.rdap_name || "n/a"],
    ["RDAP org/handle", item.rdap_org || item.rdap_handle || "n/a"],
    ["RDAP ASN", item.rdap_asn || (activeAsnNumber.value ? formatAsn(activeAsnNumber.value) : "n/a")],
    ["RDAP range", item.rdap_range || "n/a"],
    ["RDAP type", item.rdap_type || "n/a"],
    ["Registered", item.rdap_registered || "n/a"],
    ["Abuse contact", item.rdap_abuse || "n/a"],
    ["Registry/source", item.rdap_source || activeAsn.value?.registry || "n/a"]
  ]
})

const asnPrefixStats = computed(() => {
  const prefixes = activeAsn.value?.prefixes || []
  const ipv6 = prefixes.filter((prefix) => prefix.includes(":"))
  const ipv4 = prefixes.filter((prefix) => !prefix.includes(":"))

  return {
    total: prefixes.length,
    ipv4: ipv4.length,
    ipv6: ipv6.length,
    first: prefixes[0] || "n/a"
  }
})

const asnRows = computed(() => {
  const asn = activeAsn.value
  if (!asn) {
    return []
  }

  return [
    ["ASN", formatAsn(asn.asn)],
    ["Holder", asn.holder || "n/a"],
    ["Network name", asn.name || "n/a"],
    ["Country", asn.country_code || "n/a"],
    ["Registry", asn.registry || "n/a"],
    ["Allocated", asn.allocated || "n/a"],
    ["Data source", asn.source || "n/a"],
    ["Announced prefixes", numberFormatter.format(asnPrefixStats.value.total)]
  ]
})

const asnPrefixPreview = computed(() => (activeAsn.value?.prefixes || []).slice(0, 48))
const asnHiddenPrefixCount = computed(() => Math.max((activeAsn.value?.prefixes.length || 0) - asnPrefixPreview.value.length, 0))

const dnsRows = computed(() => {
  const dns = result.value?.dns
  if (!dns) {
    return []
  }

  return [
    ["A", listOr(dns.a, 12)],
    ["AAAA", listOr(dns.aaaa, 12)],
    ["CNAME", listOr(dns.cname, 8)],
    ["MX", listOr(dns.mx, 8)],
    ["NS", listOr(dns.ns, 8)],
    ["TXT", listOr(dns.txt, 5)],
    ["CAA", listOr(dns.caa, 8)],
    ["SOA", listOr(dns.soa, 3)]
  ]
})

const rawPayload = computed(() => (result.value ? JSON.stringify(result.value, null, 2) : ""))

const writeClipboard = async (value: string) => {
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(value)
      return
    }
  } catch {
    // Fall back to the legacy copy path below.
  }

  const textarea = document.createElement("textarea")
  textarea.value = value
  textarea.setAttribute("readonly", "")
  textarea.style.position = "fixed"
  textarea.style.opacity = "0"
  document.body.appendChild(textarea)
  textarea.select()
  document.execCommand("copy")
  document.body.removeChild(textarea)
}

const candidateConfidenceTone = (label: string) => {
  if (label === "high") {
    return "accent"
  }
  if (label === "medium") {
    return "warning"
  }
  return "info"
}

const formatCandidateSources = (sources: string[]) => {
  return sources.length ? sources.join(", ") : "n/a"
}

const lookup = async (value = query.value) => {
  const target = value.trim()

  if (!target) {
    errorMessage.value = "Enter an IP address, prefix, ASN or domain."
    return
  }

  loading.value = true
  errorMessage.value = ""
  progress.value = "Resolving target through the backend API..."

  try {
    const response = await backendFetch<LookupResponse>(`/lookup?q=${encodeURIComponent(target)}`)
    result.value = response
    progress.value = response.cached ? "Served from backend cache." : "Lookup completed from live and local sources."
    query.value = target
    await router.replace({ query: { q: target } })
    await loadHistory()
  } catch (error: any) {
    const detail = error?.data?.detail || error?.message || "Lookup failed."
    errorMessage.value = String(detail)
    progress.value = "The backend returned an error."
  } finally {
    loading.value = false
  }
}

const loadHistory = async () => {
  try {
    const params = new URLSearchParams({ limit: "12" })
    if (historySearch.value.trim()) {
      params.set("query", historySearch.value.trim())
    }
    historyItems.value = await backendFetch<HistoryRecord[]>(`/history?${params.toString()}`)
  } catch (error: any) {
    historyItems.value = []
    errorMessage.value = error?.data?.detail || error?.message || "History loading failed."
  }
}

const clearHistory = async () => {
  try {
    await backendFetch("/history", { method: "DELETE" })
    await loadHistory()
  } catch (error: any) {
    errorMessage.value = error?.data?.detail || error?.message || "History cleanup failed."
  }
}

const loadMyIp = async () => {
  const response = await backendFetch<MeResponse>("/me")
  query.value = response.ip
}

const shareUrl = async () => {
  await router.replace({ query: query.value ? { q: query.value } : {} })
  await writeClipboard(window.location.href)
}

const copyResult = async () => {
  const payload = rawPayload.value || identityRows.value.map(([label, value]) => `${label}: ${value}`).join("\n")
  await writeClipboard(payload)
}

const copyAsn = async () => {
  if (!activeAsn.value) {
    return
  }
  await writeClipboard(JSON.stringify(activeAsn.value, null, 2))
}

const selectHistory = async (target: string | null) => {
  if (!target) {
    return
  }
  query.value = target
  await lookup(target)
}

watch(
  () => route.query.q,
  (value) => {
    if (typeof value === "string" && value !== query.value) {
      query.value = value
    }
  }
)

onMounted(async () => {
  await loadHistory()

  if (query.value) {
    await lookup(query.value)
    return
  }

  try {
    await loadMyIp()
    progress.value = "Detected your current IP. Run lookup when ready."
  } catch {
    progress.value = "Backend is available, but automatic IP detection did not complete."
  }
})
</script>

<template>
  <div class="page-stack">
    <section class="hero panel panel--hero">
      <div class="hero__actions lookup-card">
        <label class="field">
          <span class="field__label">Lookup target</span>
          <input
            v-model="query"
            class="input input--large"
            type="text"
            placeholder="8.8.8.8, 1.1.1.0/24, AS15169 or example.com"
            @keyup.enter="lookup()"
          >
        </label>

        <div class="button-row">
          <button class="button button--primary" :disabled="loading" @click="lookup()">
            {{ loading ? "Looking up..." : "Lookup" }}
          </button>
          <button class="button" @click="loadMyIp">My IP</button>
          <button class="button" :disabled="!query" @click="shareUrl">Share URL</button>
          <button class="button" :disabled="!result" @click="copyResult">Copy result</button>
          <button class="button" :disabled="!result" @click="rawVisible = !rawVisible">
            {{ rawVisible ? "Hide JSON" : "Show JSON" }}
          </button>
        </div>

        <p class="status-line">{{ progress }}</p>
        <p v-if="errorMessage" class="error-line">{{ errorMessage }}</p>
      </div>
    </section>

    <section class="panel result-panel">
      <div class="panel__header panel__header--center">
        <div>
          <p class="eyebrow">Lookup result</p>
          <h2>{{ resultTitle }}</h2>
          <p class="muted">{{ resultSubtitle }}</p>
        </div>
        <SecurityBadges :security="result?.security" />
      </div>

      <div v-if="result" class="result-overview">
        <article
          v-for="card in summaryCards"
          :key="card.label"
          class="overview-card"
          :data-tone="card.tone"
        >
          <span class="overview-card__label">{{ card.label }}</span>
          <strong>{{ card.value }}</strong>
          <span class="overview-card__detail">{{ card.detail }}</span>
        </article>
      </div>
      <div v-else class="empty-state">
        Run a lookup to populate geo, RDAP, DNS, ASN and security signals.
      </div>

      <div v-if="result?.network_notes.length" class="note-list note-list--spaced">
        <p v-for="note in result.network_notes" :key="note" class="note-list__item">
          {{ note }}
        </p>
      </div>

      <pre v-if="result && rawVisible" class="code-block">{{ rawPayload }}</pre>
    </section>

    <div v-if="result" class="content-grid">
      <section class="panel">
        <div class="panel__header">
          <div>
            <p class="eyebrow">Details</p>
            <h2>Target profile</h2>
          </div>
        </div>

        <div class="details-grid">
          <div v-for="[label, value] in identityRows" :key="label" class="detail-item">
            <span class="detail-item__label">{{ label }}</span>
            <span class="detail-item__value">{{ value }}</span>
          </div>
        </div>
      </section>

      <section class="panel">
        <div class="panel__header">
          <div>
            <p class="eyebrow">Map</p>
            <h2>Location preview</h2>
          </div>
        </div>

        <LookupMap
          :latitude="result?.latitude ?? null"
          :longitude="result?.longitude ?? null"
          :label="result?.city || result?.country_name || result?.ip"
        />
      </section>
    </div>

    <section v-if="result" class="panel">
      <div class="panel__header">
        <div>
          <p class="eyebrow">Registry</p>
          <h2>RDAP and allocation data</h2>
        </div>
      </div>
      <div class="details-grid">
        <div v-for="[label, value] in registryRows" :key="label" class="detail-item">
          <span class="detail-item__label">{{ label }}</span>
          <span class="detail-item__value">{{ value }}</span>
        </div>
      </div>
    </section>

    <section v-if="activeAsn || activeAsnNumber" class="panel panel--asn">
      <div class="panel__header panel__header--center">
        <div>
          <p class="eyebrow">ASN context</p>
          <h2>Autonomous system profile</h2>
        </div>
        <button class="button" :disabled="!activeAsn" @click="copyAsn">Copy ASN JSON</button>
      </div>

      <div class="asn-profile">
        <div class="asn-profile__hero">
          <span class="asn-profile__number">{{ formatAsn(activeAsnNumber) }}</span>
          <h3>{{ activeAsn?.holder || activeAsn?.name || ownerLabel }}</h3>
          <p class="muted">
            {{ activeAsn?.country_code || result?.country_code || "country n/a" }} · {{ activeAsn?.registry || result?.rdap_source || "registry n/a" }} · {{ activeAsn?.source || result?.source || "source n/a" }}
          </p>
          <div class="badges">
            <span class="badge" data-tone="accent">{{ numberFormatter.format(asnPrefixStats.total) }} prefixes</span>
            <span class="badge" data-tone="info">IPv4: {{ numberFormatter.format(asnPrefixStats.ipv4) }}</span>
            <span class="badge" data-tone="info">IPv6: {{ numberFormatter.format(asnPrefixStats.ipv6) }}</span>
          </div>
        </div>

        <div class="details-grid details-grid--compact">
          <div v-for="[label, value] in asnRows" :key="label" class="detail-item">
            <span class="detail-item__label">{{ label }}</span>
            <span class="detail-item__value">{{ value }}</span>
          </div>
        </div>
      </div>

      <div v-if="asnPrefixPreview.length" class="prefix-section">
        <div class="section-title-row">
          <div>
            <p class="eyebrow">Routing footprint</p>
            <h3>Announced prefixes</h3>
          </div>
          <span class="muted">Showing {{ asnPrefixPreview.length }} of {{ asnPrefixStats.total }}</span>
        </div>
        <div class="prefix-cloud">
          <span v-for="prefix in asnPrefixPreview" :key="prefix" class="prefix-chip mono">{{ prefix }}</span>
          <span v-if="asnHiddenPrefixCount" class="prefix-chip prefix-chip--more">+{{ asnHiddenPrefixCount }} more</span>
        </div>
      </div>
      <div v-else class="empty-state empty-state--small">
        Prefix list is not available for this ASN yet.
      </div>
    </section>

    <section v-if="result?.query_type === 'domain'" class="panel">
      <div class="panel__header">
        <div>
          <p class="eyebrow">Domain context</p>
          <h2>DNS and routing hints</h2>
        </div>
      </div>

      <div v-if="result.routing" class="routing-box">
        <div class="details-grid">
          <div class="detail-item">
            <span class="detail-item__label">Provider</span>
            <span class="detail-item__value">{{ result.routing.provider || "n/a" }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-item__label">CDN / proxy</span>
            <span class="detail-item__value">
              {{
                result.routing.is_origin_hidden
                  ? "Edge IP is visible, origin is likely hidden"
                  : result.routing.is_cdn
                    ? "CDN detected"
                    : "No CDN hint"
              }}
            </span>
          </div>
        </div>
        <div v-if="result.routing.notes.length" class="note-list">
          <p v-for="note in result.routing.notes" :key="note" class="note-list__item">
            {{ note }}
          </p>
        </div>
      </div>

      <div v-if="dnsRows.length" class="details-grid">
        <div v-for="[label, value] in dnsRows" :key="label" class="detail-item">
          <span class="detail-item__label">{{ label }}</span>
          <span class="detail-item__value">{{ value }}</span>
        </div>
      </div>
      <div v-else class="empty-state">
        DNS profile is not available for this domain.
      </div>
    </section>

    <section v-if="result?.query_type === 'domain' && result.origin_candidates.length" class="panel">
      <div class="panel__header">
        <div>
          <p class="eyebrow">Origin discovery</p>
          <h2>Potential origin or related infrastructure</h2>
        </div>
      </div>

      <div class="history-list">
        <article v-for="candidate in result.origin_candidates" :key="candidate.hostname" class="origin-card">
          <div class="history-card__top">
            <strong>{{ candidate.hostname }}</strong>
            <span class="muted">{{ formatCandidateSources(candidate.sources) }}</span>
          </div>

          <div class="details-grid">
            <div class="detail-item">
              <span class="detail-item__label">Confidence</span>
              <span class="detail-item__value">
                {{ candidate.confidence }} / 100 ({{ candidate.confidence_label }})
              </span>
            </div>
            <div class="detail-item">
              <span class="detail-item__label">Primary source</span>
              <span class="detail-item__value">{{ candidate.source }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-item__label">Selected IP</span>
              <span class="detail-item__value">{{ candidate.selected_ip || "n/a" }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-item__label">Resolved IPs</span>
              <span class="detail-item__value">
                {{ listOr(candidate.resolved_ips, 8) }}
              </span>
            </div>
            <div class="detail-item">
              <span class="detail-item__label">Provider</span>
              <span class="detail-item__value">{{ candidate.provider || "n/a" }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-item__label">Rule</span>
              <span class="detail-item__value">{{ candidate.matched_rule || "derived" }}</span>
            </div>
          </div>

          <div class="badges">
            <span class="badge" :data-tone="candidateConfidenceTone(candidate.confidence_label)">
              {{ candidate.confidence_label }} confidence
            </span>
            <span class="badge" :data-tone="candidate.is_cdn ? 'warning' : 'clean'">
              {{ candidate.is_cdn ? "CDN-like" : "Non-CDN" }}
            </span>
            <span class="badge" :data-tone="candidate.same_as_edge ? 'warning' : 'info'">
              {{ candidate.same_as_edge ? "Same as edge" : "Different from edge" }}
            </span>
          </div>

          <div v-if="candidate.evidence.length" class="note-list">
            <p v-for="item in candidate.evidence" :key="item" class="note-list__item">
              {{ item }}
            </p>
          </div>

          <div class="note-list">
            <p v-for="note in candidate.notes" :key="note" class="note-list__item">
              {{ note }}
            </p>
          </div>
        </article>
      </div>
    </section>

    <section class="panel">
      <div class="panel__header">
        <div>
          <p class="eyebrow">History</p>
          <h2>Latest stored lookups</h2>
        </div>
        <div class="button-row">
          <input v-model="historySearch" class="input input--small" type="text" placeholder="Search history" @keyup.enter="loadHistory">
          <button class="button" @click="loadHistory">Refresh</button>
          <button class="button button--danger" @click="clearHistory">Clear</button>
        </div>
      </div>

      <div v-if="historyItems.length" class="history-list">
        <button
          v-for="item in historyItems"
          :key="item.id"
          class="history-card"
          type="button"
          @click="selectHistory(item.query || item.ip || (item.asn ? `AS${item.asn}` : null))"
        >
          <div class="history-card__top">
            <strong>{{ item.query || item.ip || (item.asn ? `AS${item.asn}` : "Unknown") }}</strong>
            <span class="muted">{{ formatDateTime(item.ts) }}</span>
          </div>
          <div class="history-card__middle">
            <span>{{ item.country_name || item.country_code || item.org || "Unknown" }}</span>
            <span class="muted">{{ item.query_type }} · {{ item.response_time_ms ?? "n/a" }} ms · risk {{ item.risk_score }}/100</span>
          </div>
          <SecurityBadges
            :security="{
              vpn: item.vpn,
              proxy: item.proxy,
              tor: item.tor,
              i2p: item.i2p,
              datacenter: item.datacenter,
              threat: item.threat
            }"
          />
        </button>
      </div>
      <div v-else class="empty-state">
        History is still empty.
      </div>
    </section>
  </div>
</template>
