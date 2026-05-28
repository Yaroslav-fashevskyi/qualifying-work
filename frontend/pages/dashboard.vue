<script setup lang="ts">
import type { HistoryRecord, StatsResponse } from "~/types/api"

const { backendFetch } = useBackendApi()
const stats = ref<StatsResponse | null>(null)
const historyItems = ref<HistoryRecord[]>([])
const loading = ref(true)
const errorMessage = ref("")

const runtimeSince = computed(() => {
  if (!stats.value) {
    return "n/a"
  }
  return new Date(stats.value.runtime.since * 1000).toLocaleString()
})

const latestHistory = computed(() => {
  const latest = stats.value?.latest_ts
  return latest ? new Date(latest * 1000).toLocaleString() : "n/a"
})

const topRuntimeCountries = computed(() => {
  if (!stats.value) {
    return []
  }
  return Object.entries(stats.value.runtime.by_country)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 6)
})

const queryTypeRows = computed(() => {
  if (!stats.value) {
    return []
  }
  return Object.entries(stats.value.db_by_query_type)
    .sort((left, right) => right[1] - left[1])
})

const securityRows = computed(() => {
  if (!stats.value) {
    return []
  }
  return Object.entries(stats.value.db_security_hits)
    .filter(([, count]) => count > 0)
    .sort((left, right) => right[1] - left[1])
})

const loadDashboard = async () => {
  loading.value = true
  errorMessage.value = ""

  try {
    const [statsResponse, historyResponse] = await Promise.all([
      backendFetch<StatsResponse>("/stats"),
      backendFetch<HistoryRecord[]>("/history?limit=30")
    ])

    stats.value = statsResponse
    historyItems.value = historyResponse
  } catch (error: any) {
    errorMessage.value = error?.data?.detail || error?.message || "Dashboard loading failed."
  } finally {
    loading.value = false
  }
}

onMounted(loadDashboard)
</script>

<template>
  <div class="page-stack">
    <section class="hero panel panel--hero">
      <div class="hero__copy">

        <h1>Lookup analytics</h1>
      </div>

      <div class="metric-strip">
        <article class="metric-card">
          <span class="metric-card__label">Runtime lookups</span>
          <strong>{{ stats?.runtime.total_lookups ?? "—" }}</strong>
        </article>
        <article class="metric-card">
          <span class="metric-card__label">Stored history</span>
          <strong>{{ stats?.total_history ?? "—" }}</strong>
        </article>
        <article class="metric-card">
          <span class="metric-card__label">Cache hit ratio</span>
          <strong>{{ stats ? `${Math.round(stats.runtime.cache_hit_ratio * 100)}%` : "—" }}</strong>
        </article>
        <article class="metric-card">
          <span class="metric-card__label">Avg response</span>
          <strong>{{ stats ? `${stats.runtime.avg_response_ms} ms` : "—" }}</strong>
        </article>
      </div>
    </section>

    <p v-if="errorMessage" class="error-line">{{ errorMessage }}</p>

    <div v-if="loading" class="empty-state">Loading dashboard data...</div>
<div v-else-if="!stats" class="empty-state">No dashboard data available yet.</div>

    <div class="content-grid">
      <section class="panel">
        <div class="panel__header">
          <div>
            <p class="eyebrow">Query mix</p>
            <h2>Stored query types</h2>
          </div>
        </div>
        <div v-if="queryTypeRows.length" class="history-list">
          <div v-for="[type, count] in queryTypeRows" :key="type" class="detail-item">
            <span class="detail-item__label">{{ type }}</span>
            <span class="detail-item__value">{{ count }}</span>
          </div>
        </div>
        <div v-else class="empty-state">No query type data yet.</div>
      </section>

      <section class="panel">
        <div class="panel__header">
          <div>
            <p class="eyebrow">Security</p>
            <h2>Security list hits</h2>
          </div>
        </div>
        <div v-if="securityRows.length" class="history-list">
          <div v-for="[type, count] in securityRows" :key="type" class="detail-item">
            <span class="detail-item__label">{{ type }}</span>
            <span class="detail-item__value">{{ count }}</span>
          </div>
        </div>
        <div v-else class="empty-state">No VPN/proxy/TOR/threat hits recorded yet.</div>
      </section>
    </div>

    <section class="panel">
      <div class="panel__header">
        <div>
          <p class="eyebrow">Recent activity</p>
          <h2>Last 30 history records</h2>
          <p class="muted">Tracker since: {{ runtimeSince }} · Latest stored record: {{ latestHistory }}</p>
        </div>
        <button class="button" @click="loadDashboard">Refresh</button>
      </div>

      <div v-if="historyItems.length" class="table">
        <div class="table__head">
          <span>Time</span>
          <span>Query</span>
          <span>Location / Owner</span>
          <span>Perf / Risk</span>
          <span>Signals</span>
        </div>

        <div v-for="item in historyItems" :key="item.id" class="table__row">
          <span>{{ new Date(item.ts * 1000).toLocaleString() }}</span>
          <span class="mono">{{ item.query || item.ip || item.asn }}</span>
          <span>{{ item.country_name || item.country_code || item.org || "Unknown" }}</span>
          <span>{{ item.response_time_ms ?? "n/a" }} ms / {{ item.risk_score }}/100</span>
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
        </div>
      </div>
      <div v-else class="empty-state">
        No history data recorded yet.
      </div>
    </section>
  </div>
</template>
