import { fileURLToPath } from "node:url"

const appManifestStub = fileURLToPath(new URL("./app-manifest-stub.json", import.meta.url))

export default defineNuxtConfig({
  compatibilityDate: "2025-04-02",
  devtools: { enabled: false },
  experimental: {
    appManifest: false
  },
  alias: {
    "#app-manifest": appManifestStub
  },
  ssr: false,
  css: ["~/assets/css/main.css", "leaflet/dist/leaflet.css"],
  runtimeConfig: {
    public: {
      backendOrigin: process.env.NUXT_PUBLIC_BACKEND_ORIGIN || "http://127.0.0.1:8000"
    }
  },
  app: {
    head: {
      title: "IP Intelligence",
      meta: [
        {
          name: "description",
          content: "Nuxt frontend for IP, domain and ASN intelligence backed by FastAPI."
        }
      ]
    }
  }
})
