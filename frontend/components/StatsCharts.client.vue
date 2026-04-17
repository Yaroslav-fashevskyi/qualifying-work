<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from "vue"
import type { Chart } from "chart.js"
import type { StatsResponse } from "~/types/api"

const props = defineProps<{
  stats: StatsResponse | null
}>()

const countryCanvas = ref<HTMLCanvasElement | null>(null)
const runtimeCanvas = ref<HTMLCanvasElement | null>(null)

let countryChart: Chart | null = null
let runtimeChart: Chart | null = null

const renderCharts = async () => {
  if (!props.stats || !countryCanvas.value || !runtimeCanvas.value) {
    return
  }

  const { default: ChartJS } = await import("chart.js/auto")

  countryChart?.destroy()
  runtimeChart?.destroy()

  const dbEntries = Object.entries(props.stats.db_by_country)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 8)

  countryChart = new ChartJS(countryCanvas.value, {
    type: "bar",
    data: {
      labels: dbEntries.map(([country]) => country),
      datasets: [
        {
          label: "History records",
          data: dbEntries.map(([, count]) => count),
          backgroundColor: "#7dd3fc",
          borderColor: "#f59e0b",
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          ticks: { color: "#d7decc" },
          grid: { color: "rgba(215, 222, 204, 0.08)" }
        },
        y: {
          ticks: { color: "#d7decc" },
          grid: { color: "rgba(215, 222, 204, 0.08)" }
        }
      }
    }
  })

  const flaggedCountries = Object.keys(props.stats.runtime.by_country).length

  runtimeChart = new ChartJS(runtimeCanvas.value, {
    type: "doughnut",
    data: {
      labels: ["Lookups", "Countries seen"],
      datasets: [
        {
          data: [props.stats.runtime.total_lookups, flaggedCountries || 1],
          backgroundColor: ["#63e6be", "#f59e0b"],
          borderColor: "#0d1816",
          borderWidth: 3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#d7decc"
          }
        }
      }
    }
  })
}

watch(
  () => props.stats,
  () => {
    void renderCharts()
  },
  { immediate: true }
)

onBeforeUnmount(() => {
  countryChart?.destroy()
  runtimeChart?.destroy()
})
</script>

<template>
  <div class="chart-grid">
    <section class="panel panel--chart">
      <div class="panel__header">
        <div>
          <p class="eyebrow">History</p>
          <h2>Top countries in stored lookups</h2>
        </div>
      </div>
      <div class="chart-frame">
        <canvas ref="countryCanvas" />
      </div>
    </section>

    <section class="panel panel--chart">
      <div class="panel__header">
        <div>
          <p class="eyebrow">Runtime</p>
          <h2>Current in-memory counters</h2>
        </div>
      </div>
      <div class="chart-frame">
        <canvas ref="runtimeCanvas" />
      </div>
    </section>
  </div>
</template>
