<script setup lang="ts">
import type { HistoryRecord, LookupResponse, MeResponse } from "~/types/api"

const route = useRoute()
const router = useRouter()
const { backendFetch } = useBackendApi()

const query = ref(typeof route.query.q === "string" ? route.query.q : "")
const result = ref<LookupResponse | null>(null)
const historyItems = ref<HistoryRecord[]>([])
const progress = ref("Ready for lookup.")
const loading = ref(false)
const errorMessage = ref("")
const rawVisible = ref(false)

const details = computed(() => {
  const item = result.value
  if (!item) {
    return []
  }

  return [
    ["Query", item.query],
    ["Query type", item.query_type],
    ["Domain", item.domain || "n/a"],
    ["Selected IP", item.ip || "n/a"],
    ["Resolved IPs", item.resolved_ips.length ? item.resolved_ips.join(", ") : "n/a"],
    ["Country", item.country_name ? `${item.country_name} (${item.country_code || "n/a"})` : "n/a"],
    ["Region", item.region || "n/a"],
    ["City", item.city || "n/a"],
    ["Timezone", item.timezone || "n/a"],
    ["Coordinates", item.latitude != null && item.longitude != null ? `${item.latitude}, ${item.longitude}` : "n/a"],
    ["Organization", item.org || item.rdap_org || "n/a"],
    ["Reverse DNS", item.reverse_dns || "n/a"],
    ["RDAP Name", item.rdap_name || "n/a"],
    ["RDAP ASN", item.rdap_asn || "n/a"],
    ["RDAP Range", item.rdap_range || "n/a"],
    ["RDAP Handle", item.rdap_handle || "n/a"],
    ["Abuse Contact", item.rdap_abuse || "n/a"],
    ["Registry", item.rdap_source || "n/a"],
    ["Source", item.source || "n/a"],
    ["Cache", item.cached ? "hit" : "miss"]
  ]
})

const dnsRows = computed(() => {
  const dns = result.value?.dns
  if (!dns) {
    return []
  }

  return [
    ["A", dns.a.join(", ") || "n/a"],
    ["AAAA", dns.aaaa.join(", ") || "n/a"],
    ["CNAME", dns.cname.join(", ") || "n/a"],
    ["MX", dns.mx.join(", ") || "n/a"],
    ["NS", dns.ns.join(", ") || "n/a"],
    ["TXT", dns.txt.join(" | ") || "n/a"],
    ["CAA", dns.caa.join(" | ") || "n/a"],
    ["SOA", dns.soa.join(" | ") || "n/a"]
  ]
})

const rawPayload = computed(() => (result.value ? JSON.stringify(result.value, null, 2) : ""))

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
    errorMessage.value = "Enter an IP address or domain."
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
  historyItems.value = await backendFetch<HistoryRecord[]>("/history?limit=12")
}

const clearHistory = async () => {
  await backendFetch("/history", { method: "DELETE" })
  await loadHistory()
}

  const loadMyIp = async () => {
  const response = await backendFetch<MeResponse>("/me")
  query.value = response.ip
}

const shareUrl = async () => {
  await router.replace({ query: query.value ? { q: query.value } : {} })
  await navigator.clipboard.writeText(window.location.href)
}

const copyResult = async () => {
  const payload = rawPayload.value || details.value.map(([label, value]) => `${label}: ${value}`).join("\n")
  await navigator.clipboard.writeText(payload)
}

const selectHistory = async (ip: string) => {
  query.value = ip
  await lookup(ip)
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
      <div class="hero__copy">
        <p class="eyebrow">lookup</p>
        <h1>IP, domain and ASN lookup</h1>
        <p class="hero__text">
          Enter ipv4/ipv6 / domain
        </p>
      </div>

      <div class="hero__actions">
        <label class="field">
          <span class="field__label">Lookup target</span>
          <input
            v-model="query"
            class="input"
            type="text"
            placeholder="8.8.8.8 or example.com"
            @keyup.enter="lookup()"
          >
        </label>

        <div class="button-row">
          <button class="button button--primary" :disabled="loading" @click="lookup()">
            {{ loading ? "Looking up..." : "Lookup" }}
          </button>
          <button class="button" @click="loadMyIp">My IP</button>
          <button class="button" :disabled="!query" @click="shareUrl">Share URL</button>
          <button class="button" :disabled="!result" @click="copyResult">Copy payload</button>
          <button class="button" :disabled="!result" @click="rawVisible = !rawVisible">
            {{ rawVisible ? "Hide JSON" : "Show JSON" }}
          </button>
        </div>

        <p class="status-line">{{ progress }}</p>
        <p v-if="errorMessage" class="error-line">{{ errorMessage }}</p>
      </div>
    </section>

    <div class="content-grid">
      <section class="panel">
        <div class="panel__header">
          <div>
            <p class="eyebrow">Lookup result</p>
            <h2>{{ result?.query || "No active result" }}</h2>
          </div>
          <SecurityBadges :security="result?.security" />
        </div>

        <div v-if="result" class="details-grid">
          <div v-for="[label, value] in details" :key="label" class="detail-item">
            <span class="detail-item__label">{{ label }}</span>
            <span class="detail-item__value">{{ value }}</span>
          </div>
        </div>
        <div v-else class="empty-state">
          Run a lookup to populate geo, RDAP and security signals.
        </div>

        <pre v-if="result && rawVisible" class="code-block">{{ rawPayload }}</pre>
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

    <section v-if="result?.query_type === 'domain'" class="panel">
      <div class="panel__header">
        <div>
          <p class="eyebrow">Domain context</p>
          <h2>DNS and routing hints</h2>
        </div>
      </div>

      <div v-if="result.routing" class="routing-box">
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

    <section
      v-if="result?.query_type === 'domain' && result.origin_candidates.length"
      class="panel"
    >
      <div class="panel__header">
        <div>
          <p class="eyebrow">Origin discovery</p>
          <h2>Potential origin or related infrastructure</h2>
        </div>
      </div>

      <div class="history-list">
        <article
          v-for="candidate in result.origin_candidates"
          :key="candidate.hostname"
          class="origin-card"
        >
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
                {{ candidate.resolved_ips.length ? candidate.resolved_ips.join(", ") : "n/a" }}
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
          @click="selectHistory(item.query || item.ip)"
        >
          <div class="history-card__top">
            <strong>{{ item.query || item.ip }}</strong>
            <span class="muted">{{ new Date(item.ts * 1000).toLocaleString() }}</span>
          </div>
          <div class="history-card__middle">
            <span>{{ item.country_name || "Unknown country" }}</span>
            <span class="muted">{{ item.city || item.region || "No city" }}</span>
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
