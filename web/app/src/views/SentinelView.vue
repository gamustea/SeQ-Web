<template>
  <div class="sentinel-page" data-module="sentinel">
    <Topbar title="Sentinel" badge="Escaneos de Vulnerabilidades" />

    <main class="main">
      <!-- Stats -->
      <StatsRow
        :total="store.stats.total"
        :nmap="store.stats.nmap"
        :nikto="store.stats.nikto"
        :openvas="store.stats.openvas"
      />

      <!-- Tabs -->
      <ScanTabs :active="store.activeTab" @switch="store.switchTab" />

      <!-- Launch form (adapts to active tab) -->
      <ScanForm :type="store.activeTab" :launching="store.launching" @launch="handleLaunch" />

      <!-- Table -->
      <ScanTable
        :type="store.activeTab"
        :rows="currentData.results"
        :loading="currentData.loading"
        @preview="(id, type) => store.openPreview(id, type)"
        @cancel="handleCancel"
        @delete="handleDelete"
        @refresh="store.refreshCurrent()"
      />

      <!-- Scheduled Scans Panel -->
      <ScheduledScansPanel
        :scheduled="store.scheduled"
        :scheduling="store.scheduling"
        :active-tab="store.activeTab"
        @create="handleCreateScheduled"
        @deactivate="handleDeactivateScheduled"
        @delete="handleDeleteScheduled"
        @toggle-form="store.toggleScheduledForm()"
      />
    </main>

    <!-- Preview Modal -->
    <ScanPreviewModal
      :show="store.preview.show"
      :scan="store.preview.scan"
      :type="store.preview.type"
      :docs="store.preview.docs"
      :docs-loading="store.preview.docsLoading"
      @close="store.closePreview()"
      @refresh-docs="store.refreshPreviewDocs()"
      @download-doc="store.downloadDocument"
      @delete-doc="handleDeletePreviewDoc"
      @generate-pdf="handlePreviewPdf"
    />

    <!-- Details Modal -->
    <ScanDetailsModal
      :show="store.details.show"
      :scan="store.details.scan"
      :type="store.details.type"
      :docs="store.details.docs"
      :docs-loading="store.details.docsLoading"
      @close="store.closeDetails()"
      @refresh-docs="store.refreshDetailsDocs()"
      @download-doc="store.downloadDocument"
      @delete-doc="handleDeleteDetailsDoc"
      @generate-pdf="handleDetailsPdf"
    />
  </div>
</template>

<script setup>
/**
 * SentinelView — Dashboard de escaneo de vulnerabilidades.
 *
 * Orquestador que conecta el store con los componentes visuales.
 * Maneja los callbacks de acciones (lanzar, cancelar, eliminar, paginar)
 * delegando la lógica al sentinelStore.
 */
import { onMounted, computed } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StatsRow from '@/components/sentinel/StatsRow.vue'
import ScanTabs from '@/components/sentinel/ScanTabs.vue'
import ScanForm from '@/components/sentinel/ScanForm.vue'
import ScanTable from '@/components/sentinel/ScanTable.vue'
import ScanPreviewModal from '@/components/sentinel/ScanPreviewModal.vue'
import ScanDetailsModal from '@/components/sentinel/ScanDetailsModal.vue'
import ScheduledScansPanel from '@/components/sentinel/ScheduledScansPanel.vue'
import { useSentinelStore } from '@/stores/sentinelStore'

const store = useSentinelStore()

const currentData = computed(() => store.scans[store.activeTab])

onMounted(() => {
  store.loadStats()
  store.loadScans(store.activeTab)
  store.loadScheduledScans()
})

/* ── Callbacks de ScanTable ── */
async function handleCancel(id) { await store.cancelScan(id) }
async function handleDelete(id) { await store.deleteScan(id) }

/* ── Callbacks de ScanForm ── */
function handleLaunch(payload) {
  const fns = { nmap: store.launchNmap, nikto: store.launchNikto, openvas: store.launchOpenvas }
  const fn = fns[store.activeTab]
  if (fn) fn(payload)
}

/* ── Callbacks de modales ── */
async function handlePreviewPdf(id, type, useAi) {
  await store.generatePdf(id, useAi)
  await new Promise(r => setTimeout(r, 600))
  await store.refreshCurrent()
  await store.refreshPreviewDocs()
}
async function handleDetailsPdf(id, type, useAi) {
  await store.generatePdf(id, useAi)
  await new Promise(r => setTimeout(r, 600))
  await store.refreshCurrent()
  await store.refreshDetailsDocs()
}
async function handleDeletePreviewDoc(docId) { await store.deleteDocument(docId); await store.refreshPreviewDocs() }
async function handleDeleteDetailsDoc(docId) { await store.deleteDocument(docId); await store.refreshDetailsDocs() }

/* ── Callbacks de ScheduledScansPanel ── */
async function handleCreateScheduled(payload) { await store.createScheduledScan(payload) }
async function handleDeactivateScheduled(id) { await store.deactivateScheduledScan(id) }
async function handleDeleteScheduled(id) { await store.deleteScheduledScan(id) }
</script>

<style scoped>
.sentinel-page { min-height: 100vh; padding-top: var(--topbar-h); }
.main { max-width: 1200px; margin: 0 auto; padding: 1.5rem; position: relative; z-index: 1; animation: seq-fade-up 0.4s ease-out; }

@media (max-width: 768px) {
  .main { padding: 1rem; }
}
</style>
