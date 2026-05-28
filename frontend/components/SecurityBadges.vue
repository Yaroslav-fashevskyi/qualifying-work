<script setup lang="ts">
import type { SecurityFlags } from "~/types/api"

const props = defineProps<{
  security?: SecurityFlags | null
}>()

type BadgeItem = {
  key: string
  label: string
  tone: string
}

const labels = computed(() => {
  const security = props.security

  if (!security) {
    return [{ key: "clean", label: "Clean", tone: "clean" }] satisfies BadgeItem[]
  }

  const items = [
    security.tor ? { key: "tor", label: "TOR", tone: "danger" } : null,
    security.vpn ? { key: "vpn", label: "VPN", tone: "warning" } : null,
    security.proxy ? { key: "proxy", label: "Proxy", tone: "info" } : null,
    security.i2p ? { key: "i2p", label: "I2P", tone: "accent" } : null,
    security.datacenter ? { key: "dc", label: "Datacenter", tone: "info" } : null,
    security.threat ? { key: "threat", label: "Threat", tone: "danger" } : null
  ].filter((item): item is BadgeItem => Boolean(item))

  return items.length ? items : [{ key: "clean", label: "Clean", tone: "clean" }]
})
</script>

<template>
  <div class="badges">
    <span
      v-for="item in labels"
      :key="item.key"
      class="badge"
      :data-tone="item.tone"
    >
      {{ item.label }}
    </span>
  </div>
</template>
