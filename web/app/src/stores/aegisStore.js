import { defineStore } from 'pinia'
import { reactive, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

/**
 * Store de Aegis — generación de píldoras de concienciación con IA.
 *
 * Sustituye la lógica dispersa en aegis.js (521 líneas). Centraliza los
 * temas, marcas, documentos, tweaks de generación, historial y visor.
 */
export const useAegisStore = defineStore('aegis', () => {
  const { apiFetch } = useApi()
  const toast = useToastStore()

  /** Lista de temas disponibles */
  const topics = ref([])
  /** Catálogo de marcas */
  const brands = ref([])
  /** Documentos del historial del usuario */
  const documents = ref([])
  /** Tema seleccionado para generación */
  const selectedTopicId = ref(null)
  /** Documento actualmente en el visor */
  const currentDocId = ref(null)
  /** Modo de ordenación del historial */
  const sortMode = ref('date-desc')
  /** Marcas seleccionadas para la generación */
  const selectedBrands = ref([])
  /** Generación en curso */
  const generating = ref(false)
  /** Carga de historial en curso */
  const loading = ref(false)

  /** Parámetros de generación (tweaks) */
  const tweaks = reactive({
    company: '',
    language: 'es',
    tone: 'profesional',
    audienceLevel: 'mixed',
    mentionContact: '',
    sector: '',
    topicFocus: '',
  })

  /** Estado del documento en el visor */
  const viewerDoc = reactive({ loading: false, data: null })

  /* ── CARGA INICIAL ── */

  /** Carga los temas desde GET /aegis/topics */
  async function loadTopics() {
    try {
      const res = await apiFetch('/aegis/topics')
      if (res?.ok) {
        const data = await res.json()
        topics.value = data.topics ?? data ?? []
      }
    } catch { /* noop */ }
  }

  /** Carga el catálogo de marcas desde GET /aegis/brands. Normaliza a strings. */
  async function loadBrands() {
    try {
      const res = await apiFetch('/aegis/brands')
      if (res?.ok) {
        const data = await res.json()
        const raw = data.brands ?? data ?? []
        brands.value = raw.map(b => (typeof b === 'string' ? b : (b.name || b.label || b.value || String(b))))
      }
    } catch { /* noop */ }
  }

  /* ── HISTORIAL ── */

  /** Carga el historial de documentos del usuario desde GET /aegis/documents */
  async function loadHistory() {
    loading.value = true
    try {
      const res = await apiFetch('/aegis/documents')
      if (!res?.ok) { documents.value = []; return }
      const data = await res.json()
      documents.value = [...(data.documents ?? [])]
    } finally { loading.value = false }
  }

  /** Devuelve los documentos ordenados según el sortMode actual */
  function sortedDocuments() {
    const docs = [...documents.value]
    switch (sortMode.value) {
      case 'date-asc':
        return docs.sort((a, b) => new Date(a.generatedAt) - new Date(b.generatedAt))
      case 'name-asc':
        return docs.sort((a, b) => (a.title || '').localeCompare(b.title || ''))
      case 'status':
        return docs.sort((a, b) => (a.status || '').localeCompare(b.status || ''))
      default:
        return docs.sort((a, b) => new Date(b.generatedAt) - new Date(a.generatedAt))
    }
  }

  /* ── GENERACIÓN ── */

  /**
   * Inicia la generación asíncrona de una píldora vía POST /aegis/generate.
   * @returns {Promise<boolean>} True si la solicitud fue aceptada
   */
  async function generate() {
    if (!selectedTopicId.value) {
      toast.show('Selecciona un tema primero.', 'warn')
      return false
    }
    generating.value = true
    try {
      const payload = {
        topicId: selectedTopicId.value,
        tweaks: {
          company: tweaks.company,
          language: tweaks.language,
          tone: tweaks.tone,
          audienceLevel: tweaks.audienceLevel,
          mentionContact: tweaks.mentionContact,
          associatedBrands: [...selectedBrands.value],
          sector: tweaks.sector,
          topicFocus: tweaks.topicFocus,
        },
      }
      const res = await apiFetch('/aegis/generate', { method: 'POST', body: JSON.stringify(payload) })
      const data = await res?.json().catch(() => ({}))
      if (!res?.ok) {
        toast.show(data.message || 'Error al generar la píldora.', 'error')
        return false
      }
      toast.show(`Píldora en generación (ID: ${data.documentId})`, 'success')
      await loadHistory()
      return true
    } finally { generating.value = false }
  }

  /* ── VISOR ── */

  /**
   * Carga un documento en el visor central desde GET /aegis/document?id=<id>.
   * @param {number|string} id - ID del documento
   */
  async function loadDocument(id) {
    viewerDoc.loading = true
    viewerDoc.data = null
    currentDocId.value = id
    try {
      const res = await apiFetch(`/aegis/document?id=${id}`)
      if (!res?.ok) { toast.show('No se pudo cargar el documento.', 'error'); return }
      viewerDoc.data = await res.json()
    } finally { viewerDoc.loading = false }
  }

  /** Cierra/limpia el visor */
  function closeViewer() {
    currentDocId.value = null
    viewerDoc.data = null
  }

  /* ── ACCIONES SOBRE DOCUMENTOS ── */

  /**
   * Elimina un documento vía DELETE /aegis/document?id=<id>.
   * @param {number|string} id - ID del documento
   * @returns {Promise<boolean>}
   */
  async function deleteDocument(id) {
    const res = await apiFetch(`/aegis/document?id=${id}`, { method: 'DELETE' })
    if (!res?.ok) {
      toast.show('No se pudo eliminar el documento.', 'error')
      return false
    }
    if (currentDocId.value === id) closeViewer()
    await loadHistory()
    return true
  }

  /**
   * Descarga una exportación en el formato indicado.
   * @param {number|string} docId - ID del documento
   * @param {'md'|'html'|'json'} format - Formato de exportación
   * @returns {Promise<boolean>}
   */
  async function downloadExport(docId, format) {
    try {
      const res = await apiFetch(`/aegis/export/${docId}/download?format=${format}&inline=false`)
      if (!res?.ok) { toast.show('No se pudo exportar.', 'error'); return false }
      const blob = await res.blob()
      const cd = res.headers.get('Content-Disposition') ?? ''
      const name = cd.match(/filename="?([^";\n]+)"?/i)?.[1] ?? `documento_${docId}.${format}`
      _triggerDownload(blob, name)
      toast.show('Documento descargado.', 'success')
      return true
    } catch { toast.show('Error al descargar.', 'error'); return false }
  }

  /**
   * Abre una vista previa en Markdown en una nueva pestaña.
   * @param {number|string} docId - ID del documento
   */
  async function previewMarkdown(docId) {
    try {
      const res = await apiFetch(`/aegis/export/md/${docId}?inline=true`)
      if (!res?.ok) { toast.show('No se pudo previsualizar.', 'error'); return }
      const text = await res.text()
      const w = window.open('', '_blank')
      if (w) {
        w.document.write(`<pre style="padding:2rem;white-space:pre-wrap;font-family:monospace;line-height:1.6">${text.replace(/</g, '&lt;')}</pre>`)
      }
    } catch { toast.show('Error al previsualizar.', 'error') }
  }

  /** Descarga un blob como archivo */
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
    topics, brands, documents, selectedTopicId, currentDocId, sortMode, selectedBrands,
    generating, loading, tweaks, viewerDoc,
    loadTopics, loadBrands, loadHistory, sortedDocuments, generate,
    loadDocument, closeViewer, deleteDocument, downloadExport, previewMarkdown,
  }
})
