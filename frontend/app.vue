<script setup lang="ts">
const route = useRoute()
const { docsUrl } = useBackendApi()

const isActive = (path: string) => route.path === path
</script>

<template>
  <div class="shell">
    <header class="shell__header">
      <NuxtLink class="brand" to="/">
        <span class="brand__eyebrow">IP / Domain / ASN Intelligence</span>
        <span class="brand__title">Network Lookup</span>
      </NuxtLink>

      <nav class="nav">
        <NuxtLink :class="['nav__link', { 'nav__link--active': isActive('/') }]" to="/">
          Lookup
        </NuxtLink>
        <NuxtLink
          :class="['nav__link', { 'nav__link--active': isActive('/dashboard') }]"
          to="/dashboard"
        >
          Dashboard
        </NuxtLink>
        <a class="nav__link" :href="docsUrl" target="_blank" rel="noreferrer">API Docs</a>
      </nav>
    </header>

    <main class="shell__content">
      <NuxtPage />
    </main>
  </div>
</template>
