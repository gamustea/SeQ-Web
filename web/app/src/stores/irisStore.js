import { defineStore } from 'pinia'
import { ref, reactive } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

export const useIrisStore = defineStore('iris', () => {
  const { apiFetch } = useApi()
  const toast = useToastStore()

  const analyses = ref([])
  const loading = ref(false)
  const submitting = ref(false)
  const totalCount = ref(0)
  const page = ref(1)
  const perPage = ref(10)

  const currentId = ref(null)
  const currentReport = reactive({ loading: false, data: null })
  const currentStatus = reactive({ polling: false, status: null, progress: null })
  const pathCache = reactive(new Map())
  const currentPath = reactive({ loading: false, data: null })

  let pollTimer = null

  // Fase 2: si hay un mensaje completo (.eml arrastrado) se envía en
  // "message" para que el backend analice cuerpo, enlaces y adjuntos
  // reales; "headers" se mantiene como respaldo cuando solo se pegaron
  // cabeceras a mano.
  async function submitAnalysis({ headers, message, title } = {}) {
    submitting.value = true
    try {
      const body = message ? { message } : { headers }
      if (title) body.title = title

      const res = await apiFetch('/iris/analyze', {
        method: 'POST',
        body: JSON.stringify(body),
      })
      if (!res) return null
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        toast.show(data.error_description || data.message || 'Error al iniciar el an\u00e1lisis.', 'error')
        return null
      }
      toast.show(`An\u00e1lisis iniciado (ID: ${data.analysisId})`, 'success')
      currentId.value = data.analysisId
      currentReport.data = null
      await fetchResults()
      startPolling(data.analysisId)
      return data.analysisId
    } finally {
      submitting.value = false
    }
  }

  async function fetchResults(pg = page.value, pp = perPage.value) {
    loading.value = true
    try {
      const params = new URLSearchParams({ page: pg, per_page: pp })
      const res = await apiFetch(`/iris/results?${params}`)
      if (!res?.ok) { analyses.value = []; return }
      const data = await res.json()
      analyses.value = data.analyses ?? []
      totalCount.value = data.total ?? 0
    } finally {
      loading.value = false
    }
  }

  async function getReport(id) {
    currentReport.loading = true
    currentReport.data = null
    currentId.value = id
    try {
      const res = await apiFetch(`/iris/results/${id}`)
      if (!res?.ok) {
        if (res?.status === 409) {
          currentReport.loading = false
          return
        }
        toast.show('No se pudo cargar el reporte.', 'error')
        return
      }
      const data = await res.json()
      currentReport.data = data
      stopPolling()
      if (data?.status === 'finished') {
        pathFor(id)
      }
      return data
    } finally {
      currentReport.loading = false
    }
  }

  async function getStatus(id) {
    const params = new URLSearchParams({ id })
    const res = await apiFetch(`/iris/status?${params}`)
    if (!res?.ok) return null
    return await res.json()
  }

  async function pathFor(id) {
    if (!id) return null
    if (pathCache.has(id)) {
      currentPath.loading = false
      currentPath.data = pathCache.get(id)
      return currentPath.data
    }
    currentPath.loading = true
    currentPath.data = null
    try {
      const res = await apiFetch(`/iris/results/${id}/path`)
      if (!res?.ok) {
        currentPath.loading = false
        return null
      }
      const data = await res.json()
      pathCache.set(id, data)
      currentPath.data = data
      return data
    } finally {
      currentPath.loading = false
    }
  }

  function startPolling(id) {
    stopPolling()
    currentStatus.polling = true
    currentStatus.status = 'pending'
    currentStatus.progress = 0

    pollTimer = setInterval(async () => {
      const st = await getStatus(id)
      if (!st) return

      currentStatus.status = st.status
      currentStatus.progress = st.progress ?? null

      if (st.status === 'finished') {
        await getReport(id)
        await fetchResults()
        stopPolling()
      } else if (st.status === 'failed' || st.status === 'cancelled') {
        currentReport.data = { status: st.status }
        currentReport.loading = false
        await fetchResults()
        stopPolling()
      }
    }, 2000)
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer)
      pollTimer = null
    }
    currentStatus.polling = false
  }

  async function cancelAnalysis(id) {
    const res = await apiFetch(`/iris/analyze/${id}/cancel`, { method: 'POST' })
    if (!res?.ok) {
      toast.show('No se pudo cancelar el an\u00e1lisis.', 'error')
      return false
    }
    toast.show('An\u00e1lisis cancelado.', 'success')
    stopPolling()
    await getReport(id)
    await fetchResults()
    return true
  }

  async function deleteAnalysis(id) {
    const res = await apiFetch(`/iris/results/${id}`, { method: 'DELETE' })
    if (!res?.ok) {
      toast.show('No se pudo eliminar el an\u00e1lisis.', 'error')
      return false
    }
    toast.show('An\u00e1lisis eliminado.', 'success')
    pathCache.delete(id)
    if (currentId.value === id) {
      currentId.value = null
      currentReport.data = null
      currentPath.data = null
    }
    await fetchResults()
    return true
  }

  function selectAnalysis(id) {
    if (currentId.value === id) return
    stopPolling()
    currentReport.data = null
    currentPath.data = null
    if (id === null) {
      currentId.value = null
      currentStatus.status = null
      currentStatus.progress = null
      return
    }
    const found = analyses.value.find(a => a.analysisId === id)
    if (found && (found.status === 'pending' || found.status === 'running')) {
      currentId.value = id
      startPolling(id)
    } else if (found && found.status === 'finished') {
      getReport(id)
      pathFor(id)
    } else {
      currentId.value = id
      getReport(id)
      pathFor(id)
    }
  }

  function goToPage(pg) {
    page.value = pg
    fetchResults()
  }

  return {
    analyses, loading, submitting, totalCount, page, perPage,
    currentId, currentReport, currentStatus, currentPath,
    submitAnalysis, fetchResults, getReport, getStatus, pathFor,
    cancelAnalysis, deleteAnalysis, selectAnalysis, goToPage,
    startPolling, stopPolling,
  }
})
