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

const topRuntimeCountries = computed(() => {
  if (!stats.value) {
    return []
  }

  return Object.entries(stats.value.runtime.by_country)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 6)
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
        <p class="eyebrow">Dashboard</p>
        <h1>Dashboard</h1>
        <p class="hero__text">
          Dashboard
        </p>
      </div>

      <div class="metric-strip">
        <article class="metric-card">
          <span class="metric-card__label">Total lookups</span>
          <strong>{{ stats?.runtime.total_lookups ?? "—" }}</strong>
        </article>
        <article class="metric-card">
          <span class="metric-card__label">Countries in runtime</span>
          <strong>{{ topRuntimeCountries.length || "—" }}</strong>
        </article>
        <article class="metric-card">
          <span class="metric-card__label">Tracker since</span>
          <strong>{{ runtimeSince }}</strong>
        </article>
      </div>
    </section>

    <p v-if="errorMessage" class="error-line">{{ errorMessage }}</p>

    <StatsCharts v-if="stats" :stats="stats" />
    <div v-else-if="loading" class="empty-state">Loading dashboard data...</div>
    <div v-else class="empty-state">No dashboard data available yet.</div>

    <section class="panel">
      <div class="panel__header">
        <div>
          <p class="eyebrow">Recent activity</p>
          <h2>Last 30 history records</h2>
        </div>
        <button class="button" @click="loadDashboard">Refresh</button>
      </div>

      <div v-if="historyItems.length" class="table">
        <div class="table__head">
          <span>Time</span>
          <span>Query</span>
          <span>Location</span>
          <span>Org</span>
          <span>Signals</span>
        </div>

        <div v-for="item in historyItems" :key="item.id" class="table__row">
          <span>{{ new Date(item.ts * 1000).toLocaleString() }}</span>
          <span class="mono">{{ item.query || item.ip }}</span>
          <span>{{ item.country_name || "Unknown" }} / {{ item.city || item.region || "n/a" }}</span>
          <span>{{ item.org || "n/a" }}</span>
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
