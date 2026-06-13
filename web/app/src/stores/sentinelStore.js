import { defineStore } from 'pinia'
import { ref, reactive } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

/**
 * Store de Sentinel — gestiona escaneos, estadísticas, modales y documentos.
 *
 * Sustituye al estado disperso en sentinel.js (1,198 líneas de manipulación DOM
 * directa). Centraliza las listas de resultados por tipo (nmap, nikto, openvas),
 * la paginación, los modales de vista previa/detalle y los documentos asociados.
 */
export const useSentinelStore = defineStore('sentinel', () => {
  const { apiFetch } = useApi()
  const toast = useToastStore()

  /* ════════════════════════════════ TABS ═══════════════════════════════ */
  const activeTab = ref('nmap')

  /* ════════════════════════════════ STATS ══════════════════════════════ */
  const stats = reactive({ total: 0, nmap: 0, nikto: 0, openvas: 0 })
  const loadingStats = ref(false)

  /* ════════════════════════════════ SCANS POR TIPO ═════════════════════ */
  const scans = reactive({
    nmap:    { results: [], loading: false, page: 1, totalCount: 0, perPage: 10 },
    nikto:   { results: [], loading: false, page: 1, totalCount: 0, perPage: 10 },
    openvas: { results: [], loading: false, page: 1, totalCount: 0, perPage: 10 },
  })

  const launching = ref(false)

  /* ════════════════════════════════ PROGRAMADOS ════════════════════════ */
  const scheduled = reactive({ scans: [], loading: false })
  const scheduling = reactive({ showForm: false, submitting: false })

  /* ════════════════════════════════ MODALES ════════════════════════════ */
  const preview = reactive({ show: false, scanId: null, type: '', scan: null, docs: [], docsLoading: false })
  const details = reactive({ show: false, scanId: null, type: '', scan: null, docs: [], docsLoading: false })

  /* ════════════════════════════════ VISTA DE CARPETAS ══════════════════ */
  const viewMode = ref('full') // 'full' | 'folders'
  const folders = reactive({ items: [], loading: false })
  const folderForms = reactive({
    create: { show: false, submitting: false },
    rename: { show: false, folderId: null, name: '', submitting: false },
  })
  const moveScan = reactive({ show: false, scanId: null, folderId: null, submitting: false })

  /* ── HELPERS ── */
  /** @param {'nmap'|'nikto'|'openvas'} type */
  function _scandata(type) { return scans[type] }

  /** Busca un escaneo por ID en todas las carpetas (incluyendo unfoldered). Retorna { folder, idx } o null. */
  function _findScanInFolders(scanId) {
    for (const folder of folders.items) {
      const idx = (folder.scans || []).findIndex(s => s.id === scanId)
      if (idx !== -1) return { folder, idx }
    }
    return null
  }

  /** Busca una carpeta por ID. */
  function _findFolder(folderId) {
    return folders.items.find(f => f.id === folderId)
  }

  /** Obtiene (o crea) la pseudo-carpeta unfoldered. Siempre la sitúa primera. */
  function _getUnfoldered() {
    let unf = folders.items.find(f => f.id === null)
    if (!unf) {
      unf = { id: null, name: 'Sin carpeta', scans: [], scanCount: 0 }
      folders.items.unshift(unf)
    }
    return unf
  }

  /* ════════════════════════════════ STATS ══════════════════════════════ */
  /** Carga los contadores de escaneos desde el endpoint de stats. */
  async function loadStats() {
    loadingStats.value = true
    try {
      const res = await apiFetch('/sentinel/stats')
      if (!res?.ok) return
      const data = await res.json()
      stats.nmap    = data.nmap    ?? 0
      stats.nikto   = data.nikto   ?? 0
      stats.openvas = data.openvas ?? 0
      stats.total   = data.total   ?? 0
    } catch { /* noop */ }
    finally { loadingStats.value = false }
  }

  /* ════════════════════════════════ SCANS ═════════════════════════════ */
  /** Carga una pagina de resultados para un tipo de escaneo. */
  async function loadScans(type) {
    const d = _scandata(type)
    d.loading = true
    try {
      const params = new URLSearchParams({ type, page: d.page, per_page: d.perPage })
      const res = await apiFetch(`/sentinel/results?${params}`)
      if (!res?.ok) { d.results = []; return }
      const data = await res.json()
      d.results = data.results ?? []
      d.totalCount = data.totalCount ?? 0
    } finally { d.loading = false }
  }

  /** Cambia de pestana y carga los resultados desde pagina 1. */
  function switchTab(type) {
    activeTab.value = type
    const d = _scandata(type)
    d.page = 1
    loadScans(type)
    loadFolders()
  }

  /** Refresca la pestaña activa y las estadísticas. */
  async function refreshCurrent() {
    await loadScans(activeTab.value)
    await loadStats()
  }

  /** Navega a una pagina concreta para el tipo activo. */
  function goToPage(type, page) {
    const d = _scandata(type)
    d.page = page
    loadScans(type)
  }

  /* ════════════════════════════════ LANZAR ════════════════════════════ */
  /** Lanza un escaneo Nmap y refresca los datos.*/
  async function launchNmap(payload) {
    return _launch('/sentinel/nmap', payload, 'nmap')
  }
  /** Lanza un escaneo Nikto. */
  async function launchNikto(payload) {
    return _launch('/sentinel/nikto', payload, 'nikto')
  }
  /** Lanza un escaneo OpenVAS. */
  async function launchOpenvas(payload) {
    return _launch('/sentinel/openvas', payload, 'openvas')
  }

  async function _launch(endpoint, payload, type) {
    launching.value = true
    try {
      const res = await apiFetch(endpoint, { method: 'POST', body: JSON.stringify(payload) })
      const data = await res?.json().catch(() => ({}))
      if (!res?.ok) {
        toast.show(data.error_description || data.message || 'Error al lanzar el escaneo.', 'error')
        return false
      }
      const id = data.scanIds ? data.scanIds.join(', ') : data.scanId
      toast.show(`Escaneo ${type.toUpperCase()} iniciado (ID: ${id})`, 'success')
      await refreshCurrent()
      await loadFolders()
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    } finally { launching.value = false }
  }

  /* ════════════════════════════════ ACCIONES DE FILA ══════════════════ */
  /** Elimina un escaneo por ID. Actualiza el estado local sin refetch completo. */
  async function deleteScan(id) {
    const res = await apiFetch(`/sentinel/${id}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo eliminar el escaneo.', 'error'); return false }

    const hit = _findScanInFolders(id)
    if (hit) {
      hit.folder.scans.splice(hit.idx, 1)
      hit.folder.scanCount = Math.max(0, (hit.folder.scanCount || 0) - 1)
    }

    const d = _scandata(activeTab.value)
    const tableIdx = d.results.findIndex(s => s.id === id)
    if (tableIdx !== -1) {
      d.results.splice(tableIdx, 1)
      d.totalCount = Math.max(0, d.totalCount - 1)

      if (d.results.length === 0 && d.totalCount > 0 && d.page > 1) {
        d.page--
        await loadScans(activeTab.value)
      } else if (d.results.length < d.perPage && d.totalCount > d.page * d.perPage) {
        await loadScans(activeTab.value)
      }
    }

    await loadStats()
    return true
  }

  /** Cancela un escaneo en ejecución. Actualiza el badge local sin refetch. */
  async function cancelScan(id) {
    const res = await apiFetch(`/sentinel/scans/${id}/cancel`, { method: 'POST' })
    if (!res?.ok) {
      const data = await res?.json().catch(() => ({}))
      toast.show(data.message || 'No se pudo cancelar el escaneo.', 'error')
      return false
    }

    const hit = _findScanInFolders(id)
    if (hit) hit.folder.scans[hit.idx].status = 'cancelled'

    const d = _scandata(activeTab.value)
    const tableHit = d.results.find(s => s.id === id)
    if (tableHit) tableHit.status = 'cancelled'

    return true
  }

  /* ════════════════════════════════ VISTA PREVIA ══════════════════════ */
  /** Abre el modal de vista previa y carga scan + documentos. */
  async function openPreview(scanId, type) {
    preview.scanId = scanId
    preview.type = type
    preview.show = true
    preview.scan = null
    preview.docs = []
    preview.docsLoading = true

    try {
      const [scanRes, docsRes] = await Promise.all([
        apiFetch(`/sentinel/results/${scanId}`),
        apiFetch(`/sentinel/scan/${scanId}/documents`),
      ])
      if (scanRes?.ok) {
        const data = await scanRes.json()
        preview.scan = data.result ?? data
      }
      if (docsRes?.ok) {
        const data = await docsRes.json()
        preview.docs = data.documents ?? []
      }
    } catch { /* noop */ }
    finally { preview.docsLoading = false }
  }

  /** Cierra el modal de vista previa. */
  function closePreview() {
    preview.show = false
    preview.scanId = null
    preview.scan = null
    preview.docs = []
  }

  /** Refresca los documentos dentro del modal de vista previa. */
  async function refreshPreviewDocs() {
    if (!preview.scanId) return
    preview.docsLoading = true
    try {
      const res = await apiFetch(`/sentinel/scan/${preview.scanId}/documents`)
      if (res?.ok) {
        const data = await res.json()
        preview.docs = data.documents ?? []
      }
    } finally { preview.docsLoading = false }
  }

  /* ════════════════════════════════ DETALLES ══════════════════════════ */
  /** Abre el modal de detalles completos. */
  async function openDetails(scanId, type) {
    details.scanId = scanId
    details.type = type
    details.show = true
    details.scan = null
    details.docs = []
    details.docsLoading = true

    try {
      const [scanRes, docsRes] = await Promise.all([
        apiFetch(`/sentinel/results/${scanId}`),
        apiFetch(`/sentinel/scan/${scanId}/documents`),
      ])
      if (scanRes?.ok) {
        const data = await scanRes.json()
        details.scan = data.result ?? data
      }
      if (docsRes?.ok) {
        const data = await docsRes.json()
        details.docs = data.documents ?? []
      }
    } finally { details.docsLoading = false }
  }

  /** Cierra el modal de detalles. */
  function closeDetails() {
    details.show = false
    details.scanId = null
    details.scan = null
    details.docs = []
  }

  /** Refresca documentos en el modal de detalles. */
  async function refreshDetailsDocs() {
    if (!details.scanId) return
    details.docsLoading = true
    try {
      const res = await apiFetch(`/sentinel/scan/${details.scanId}/documents`)
      if (res?.ok) {
        const data = await res.json()
        details.docs = data.documents ?? []
      }
    } finally { details.docsLoading = false }
  }

  /* ════════════════════════════════ DOCUMENTOS PDF ════════════════════ */
  /** Solicita la generación de un PDF para un escaneo (opcionalmente con IA). */
  async function generatePdf(scanId, useAi = false) {
    const res = await apiFetch('/sentinel/generate-pdf', {
      method: 'POST',
      body: JSON.stringify({ id: scanId, aiReport: useAi }),
    })
    if (!res?.ok) {
      const data = await res?.json().catch(() => ({}))
      toast.show(data.message || 'Error al generar documento', 'error')
      return false
    }
    toast.show('Documento en generación...', 'success')
    return true
  }

  /** Descarga un documento PDF por ID. */
  async function downloadDocument(docId) {
    try {
      const res = await apiFetch(`/sentinel/document/${docId}/download`)
      if (!res?.ok) { toast.show('No se pudo descargar el documento.', 'error'); return false }
      const blob = await res.blob()
      const cd = res.headers.get('Content-Disposition') ?? ''
      const name = cd.match(/filename="?([^";\n]+)"?/i)?.[1] ?? `scan_${docId}.pdf`
      _triggerDownload(blob, name)
      toast.show('Documento descargado.', 'success')
      return true
    } catch (e) {
      toast.show('Error al descargar: ' + e.message, 'error')
      return false
    }
  }

  /** Elimina un documento por ID. */
  async function deleteDocument(docId) {
    const res = await apiFetch(`/sentinel/document/${docId}`, { method: 'DELETE' })
    if (!res?.ok) {
      const err = await res?.json().catch(() => ({}))
      toast.show(err.error || 'No se pudo eliminar el documento.', 'error')
      return false
    }
    toast.show('Documento eliminado.', 'success')
    return true
  }

  /* ════════════════════════════════ PROGRAMADOS ════════════════════════ */
  /** Carga los escaneos programados del usuario. */
  async function loadScheduledScans() {
    scheduled.loading = true
    try {
      const res = await apiFetch('/sentinel/scheduled-scans')
      if (!res?.ok) { scheduled.scans = []; return }
      const data = await res.json()
      scheduled.scans = data.scheduledScans ?? []
    } finally { scheduled.loading = false }
  }

  /** Crea un nuevo escaneo programado. */
  async function createScheduledScan(payload) {
    scheduling.submitting = true
    try {
      const res = await apiFetch('/sentinel/scheduled-scans', { method: 'POST', body: JSON.stringify(payload) })
      const data = await res?.json().catch(() => ({}))
      if (!res?.ok) {
        toast.show(data.error_description || data.message || 'Error al crear escaneo programado.', 'error')
        return false
      }
      toast.show(`Escaneo programado creado (ID: ${data.programedScanId})`, 'success')
      await loadScheduledScans()
      scheduling.showForm = false
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    } finally { scheduling.submitting = false }
  }

  /** Revoca (desactiva) un escaneo programado. */
  async function deactivateScheduledScan(id) {
    const res = await apiFetch(`/sentinel/scheduled-scans/${id}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo revocar el escaneo programado.', 'error'); return false }
    toast.show('Escaneo programado revocado.', 'success')
    await loadScheduledScans()
    return true
  }

  /** Elimina permanentemente un escaneo programado. */
  async function deleteScheduledScan(id) {
    const res = await apiFetch(`/sentinel/scheduled-scans/${id}/permanent`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo eliminar el escaneo programado.', 'error'); return false }
    toast.show('Escaneo programado eliminado.', 'success')
    await loadScheduledScans()
    return true
  }

  /** Muestra/oculta el formulario de creacion. */
  function toggleScheduledForm() {
    scheduling.showForm = !scheduling.showForm
  }

  /* ════════════════════════════════ CARPETAS ═══════════════════════════ */
  async function loadFolders() {
    folders.loading = true
    try {
      const res = await apiFetch('/sentinel/folders')
      if (!res?.ok) { folders.items = []; return }
      const data = await res.json()
      folders.items = data.folders ?? []
      // Append the virtual unfoldered group as a folder-like entry
      if (data.unfoldered) folders.items.push(data.unfoldered)
    } catch { folders.items = [] }
    finally { folders.loading = false }
  }

  function setViewMode(mode) {
    viewMode.value = mode
    if (mode === 'folders') {
      if (!folders.items.length) loadFolders()
    } else {
      refreshCurrent()
    }
  }

  async function createFolder(name) {
    folderForms.create.submitting = true
    try {
      const res = await apiFetch('/sentinel/folders', { method: 'POST', body: JSON.stringify({ name }) })
      const data = await res?.json().catch(() => ({}))
      if (!res?.ok) {
        toast.show(data.error_description || data.message || 'Error al crear la carpeta.', 'error')
        return false
      }
      const now = new Date().toISOString()
      folders.items.splice(folders.items.findIndex(f => f.id === null) + 1, 0, {
        id: data.folderId, name, scans: [], scanCount: 0, createdAt: now, updatedAt: now,
      })
      toast.show(`Carpeta "${name}" creada`, 'success')
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    } finally { folderForms.create.submitting = false }
  }

  async function renameFolder(folderId, name) {
    folderForms.rename.submitting = true
    try {
      const res = await apiFetch(`/sentinel/folders/${folderId}`, {
        method: 'PUT',
        body: JSON.stringify({ name }),
      })
      const data = await res?.json().catch(() => ({}))
      if (!res?.ok) {
        toast.show(data.error_description || data.message || 'Error al renombrar la carpeta.', 'error')
        return false
      }
      const folder = _findFolder(folderId)
      if (folder) folder.name = name
      toast.show('Carpeta renombrada', 'success')
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    } finally { folderForms.rename.submitting = false }
  }

  async function deleteFolder(folderId) {
    const res = await apiFetch(`/sentinel/folders/${folderId}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo eliminar la carpeta.', 'error'); return false }

    const idx = folders.items.findIndex(f => f.id === folderId)
    if (idx !== -1) {
      const folder = folders.items[idx]
      if (folder.scans?.length) {
        const unf = _getUnfoldered()
        unf.scans.push(...folder.scans)
        unf.scanCount = (unf.scanCount || 0) + folder.scans.length
      }
      folders.items.splice(idx, 1)
    }

    toast.show('Carpeta eliminada.', 'success')
    return true
  }

  async function moveScanToFolder(scanId, folderId) {
    moveScan.submitting = true
    try {
      const res = await apiFetch(`/sentinel/folders/${folderId}/scans`, {
        method: 'POST',
        body: JSON.stringify({ scanId }),
      })
      const data = await res?.json().catch(() => ({}))
      if (!res?.ok) {
        toast.show(data.error_description || data.message || 'Error al mover el escaneo.', 'error')
        return false
      }
      toast.show('Escaneo movido a la carpeta.', 'success')
      await loadFolders()
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    } finally { moveScan.submitting = false }
  }

  async function removeScanFromFolder(scanId, folderId) {
    const res = await apiFetch(`/sentinel/folders/${folderId}/scans/${scanId}`, { method: 'DELETE' })
    if (!res?.ok) { toast.show('No se pudo quitar el escaneo de la carpeta.', 'error'); return false }

    const folder = _findFolder(folderId)
    if (folder) {
      const idx = (folder.scans || []).findIndex(s => s.id === scanId)
      if (idx !== -1) {
        const [scan] = folder.scans.splice(idx, 1)
        folder.scanCount = Math.max(0, (folder.scanCount || 0) - 1)
        const unf = _getUnfoldered()
        unf.scans.push(scan)
        unf.scanCount = (unf.scanCount || 0) + 1
      }
    }

    toast.show('Escaneo eliminado de la carpeta.', 'success')
    return true
  }

  async function addScansToFolder(scanIds, folderId) {
    try {
      const res = await apiFetch(`/sentinel/folders/${folderId}/scans/batch`, {
        method: 'POST',
        body: JSON.stringify({ scanIds }),
      })
      const data = await res?.json().catch(() => ({}))
      if (!res?.ok) {
        toast.show(data.error_description || data.message || 'Error al añadir escaneos a la carpeta.', 'error')
        return false
      }
      toast.show(`${scanIds.length} escaneo(s) añadido(s) a la carpeta.`, 'success')
      await loadFolders()
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    }
  }

  /** Elimina multiples escaneos de forma masiva. */
  async function bulkDeleteScans(scanIds) {
    try {
      const res = await apiFetch('/sentinel/scans/bulk-delete', {
        method: 'POST',
        body: JSON.stringify({ scanIds }),
      })
      const data = await res?.json().catch(() => ({}))
      if (!res?.ok) {
        toast.show(data.error_description || data.message || 'Error al eliminar escaneos.', 'error')
        return false
      }
      toast.show(`${data.deletedCount ?? scanIds.length} escaneo(s) eliminado(s).`, 'success')
      await refreshCurrent()
      await loadFolders()
      await loadStats()
      return true
    } catch {
      toast.show('No se pudo conectar con la API.', 'error')
      return false
    }
  }

  function openMoveScan(scanId, currentFolderId) {
    moveScan.show = true
    moveScan.scanId = scanId
    moveScan.folderId = currentFolderId
  }

  function closeMoveScan() {
    moveScan.show = false
    moveScan.scanId = null
    moveScan.folderId = null
  }

  /* ── UTIL ── */
  function _triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    setTimeout(() => { URL.revokeObjectURL(url); a.remove() }, 1000)
  }

  return {
    activeTab, stats, loadingStats, scans, launching,
    scheduled, scheduling,
    preview, details,
    viewMode, folders, folderForms, moveScan,
    loadStats, loadScans, switchTab, refreshCurrent, goToPage,
    launchNmap, launchNikto, launchOpenvas,
    deleteScan, cancelScan,
    loadScheduledScans, createScheduledScan, deactivateScheduledScan, deleteScheduledScan, toggleScheduledForm,
    openPreview, closePreview, refreshPreviewDocs,
    openDetails, closeDetails, refreshDetailsDocs,
    generatePdf, downloadDocument, deleteDocument,
    setViewMode, loadFolders,
    createFolder, renameFolder, deleteFolder,
    moveScanToFolder, removeScanFromFolder,
    openMoveScan, closeMoveScan,
    addScansToFolder, bulkDeleteScans,
  }
})
