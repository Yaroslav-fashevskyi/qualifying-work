<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue"

const props = defineProps<{
  latitude: number | null
  longitude: number | null
  label?: string
}>()

const mapElement = ref<HTMLElement | null>(null)

let map: import("leaflet").Map | null = null
let circle: import("leaflet").CircleMarker | null = null

const renderMap = async () => {
  if (!mapElement.value || props.latitude == null || props.longitude == null) {
    return
  }

  const L = await import("leaflet")

  if (!map) {
    map = L.map(mapElement.value, {
      zoomControl: true,
      scrollWheelZoom: false
    })

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18,
      attribution: "&copy; OpenStreetMap"
    }).addTo(map)
  }

  const position: [number, number] = [props.latitude, props.longitude]

  if (!circle) {
    circle = L.circleMarker(position, {
      radius: 8,
      weight: 2,
      color: "#f7f4ea",
      fillColor: "#63e6be",
      fillOpacity: 0.95
    }).addTo(map)
  } else {
    circle.setLatLng(position)
  }

  if (props.label) {
    circle.bindTooltip(props.label, { direction: "top" })
  }

  map.setView(position, 8, { animate: false })
  await nextTick()
  map.invalidateSize()
}

onMounted(renderMap)

watch(
  () => [props.latitude, props.longitude, props.label],
  () => {
    void renderMap()
  }
)

onBeforeUnmount(() => {
  map?.remove()
  map = null
  circle = null
})
</script>

<template>
  <div v-if="latitude != null && longitude != null" ref="mapElement" class="map-panel" />
  <div v-else class="empty-state empty-state--compact">
    No coordinates available for this result.
  </div>
</template>
