export const useBackendApi = () => {
  const config = useRuntimeConfig()
  const backendOrigin = String(config.public.backendOrigin || "http://127.0.0.1:8000").replace(/\/$/, "")
  const apiBase = `${backendOrigin}/api`
  const docsUrl = `${backendOrigin}/docs`

  const apiUrl = (path: string) => `${apiBase}${path.startsWith("/") ? path : `/${path}`}`

  const backendFetch = <T>(path: string, options?: Parameters<typeof $fetch>[1]) => {
    return $fetch<T>(apiUrl(path), options)
  }

  return {
    backendOrigin,
    apiBase,
    docsUrl,
    apiUrl,
    backendFetch
  }
}
