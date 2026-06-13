<template>
  <div class="sentinel-page">
    <StarBackground />
    <Topbar title="Sentinel" badge="Escaneos de Vulnerabilidades" />

    <main class="main">
      <StatsRow :total="store.stats.total" :nmap="store.stats.nmap" :nikto="store.stats.nikto" :openvas="store.stats.openvas" />
      <ViewToggle v-model="store.viewMode" />
      <template v-if="store.viewMode === 'full'">
        <ScanTabs :active="store.activeTab" @switch="store.switchTab" />
        <ScanForm :type="store.activeTab" :launching="store.launching" @launch="handleLaunch" />
        <ScanTable :type="store.activeTab" :rows="currentData.results" :loading="currentData.loading" :current-page="currentData.page" :total-count="currentData.totalCount" :per-page="currentData.perPage"
          @preview="(id, type) => store.openPreview(id, type)" @cancel="handleCancel" @delete="handleDelete" @refresh="store.refreshCurrent()" @page-change="page => store.goToPage(store.activeTab, page)" />
      </template>
      <ScanFolderView v-else
        :folders="store.folders.items" :loading="store.folders.loading"
        @refresh="store.loadFolders()"
        @preview="(id, type) => store.openPreview(id, type)"
        @cancel="handleCancel"
        @delete="handleDelete"
        @create-folder="store.folderForms.create.show = true"
        @rename-folder="handleRenameFolder"
        @delete-folder="handleDeleteFolder"
        @move-scan="handleOpenMoveScan"
        @remove-scan="handleRemoveScan" />
      <ScheduledScansPanel :scheduled="store.scheduled" :scheduling="store.scheduling" :active-tab="store.activeTab" @create="handleCreateScheduled" @deactivate="handleDeactivateScheduled" @delete="handleDeleteScheduled" @toggle-form="store.toggleScheduledForm()" />
    </main>

    <ScanPreviewModal :show="store.preview.show" :scan="store.preview.scan" :type="store.preview.type" :docs="store.preview.docs" :docs-loading="store.preview.docsLoading"
      @close="store.closePreview()" @refresh-docs="store.refreshPreviewDocs()" @download-doc="store.downloadDocument" @delete-doc="handleDeletePreviewDoc" @generate-pdf="handlePreviewPdf" />
    <ScanDetailsModal :show="store.details.show" :scan="store.details.scan" :type="store.details.type" :docs="store.details.docs" :docs-loading="store.details.docsLoading"
      @close="store.closeDetails()" @refresh-docs="store.refreshDetailsDocs()" @download-doc="store.downloadDocument" @delete-doc="handleDeleteDetailsDoc" @generate-pdf="handleDetailsPdf" />
    <FolderFormModal
      :show="store.folderForms.create.show"
      title="Nueva carpeta"
      :submitting="store.folderForms.create.submitting"
      @close="store.folderForms.create.show = false"
      @submit="async name => { if (await store.createFolder(name)) store.folderForms.create.show = false }" />
    <FolderFormModal
      :show="store.folderForms.rename.show"
      title="Renombrar carpeta"
      :initial-name="store.folderForms.rename.name"
      :submitting="store.folderForms.rename.submitting"
      @close="store.folderForms.rename.show = false"
      @submit="async name => { if (await store.renameFolder(store.folderForms.rename.folderId, name)) store.folderForms.rename.show = false }" />
    <MoveScanModal
      :show="store.moveScan.show"
      :scan-id="store.moveScan.scanId"
      :current-folder-id="store.moveScan.folderId"
      :folders="store.folders.items"
      :submitting="store.moveScan.submitting"
      @close="store.closeMoveScan()"
      @move="async folderId => { if (await store.moveScanToFolder(store.moveScan.scanId, folderId)) store.closeMoveScan() }" />
  </div>
</template>

<script setup>
import { onMounted, computed } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import StatsRow from '@/components/sentinel/StatsRow.vue'
import ViewToggle from '@/components/sentinel/ViewToggle.vue'
import ScanTabs from '@/components/sentinel/ScanTabs.vue'
import ScanForm from '@/components/sentinel/ScanForm.vue'
import ScanTable from '@/components/sentinel/ScanTable.vue'
import ScanFolderView from '@/components/sentinel/ScanFolderView.vue'
import ScanPreviewModal from '@/components/sentinel/ScanPreviewModal.vue'
import ScanDetailsModal from '@/components/sentinel/ScanDetailsModal.vue'
import FolderFormModal from '@/components/sentinel/FolderFormModal.vue'
import MoveScanModal from '@/components/sentinel/MoveScanModal.vue'
import ScheduledScansPanel from '@/components/sentinel/ScheduledScansPanel.vue'
import { useSentinelStore } from '@/stores/sentinelStore'

const store = useSentinelStore()
const currentData = computed(() => store.scans[store.activeTab])

onMounted(() => { store.loadStats(); store.loadScans(store.activeTab); store.loadScheduledScans() })

async function handleCancel(id) { await store.cancelScan(id) }
async function handleDelete(id) { await store.deleteScan(id) }
function handleLaunch(payload) { const fns = { nmap: store.launchNmap, nikto: store.launchNikto, openvas: store.launchOpenvas }; const fn = fns[store.activeTab]; if (fn) fn(payload) }
function handleRenameFolder(folder) { store.folderForms.rename = { show: true, folderId: folder.id, name: folder.name, submitting: false } }
async function handleDeleteFolder(folderId) { if (confirm('¿Eliminar esta carpeta? Los escaneos no se borrarán, solo quedarán sin carpeta.')) await store.deleteFolder(folderId) }
function handleOpenMoveScan(scanId, folderId) { store.openMoveScan(scanId, folderId) }
async function handleRemoveScan(scanId, folderId) { await store.removeScanFromFolder(scanId, folderId) }
async function handlePreviewPdf(id, type, useAi) { await store.generatePdf(id, useAi); await new Promise(r => setTimeout(r, 600)); await store.refreshCurrent(); await store.refreshPreviewDocs() }
async function handleDetailsPdf(id, type, useAi) { await store.generatePdf(id, useAi); await new Promise(r => setTimeout(r, 600)); await store.refreshCurrent(); await store.refreshDetailsDocs() }
async function handleDeletePreviewDoc(docId) { await store.deleteDocument(docId); await store.refreshPreviewDocs() }
async function handleDeleteDetailsDoc(docId) { await store.deleteDocument(docId); await store.refreshDetailsDocs() }
async function handleCreateScheduled(payload) { await store.createScheduledScan(payload) }
async function handleDeactivateScheduled(id) { await store.deactivateScheduledScan(id) }
async function handleDeleteScheduled(id) { await store.deleteScheduledScan(id) }
</script>

<style scoped>
.sentinel-page { min-height: 100vh; padding-top: var(--topbar-h); position: relative; }
.main { max-width: 1100px; margin: 0 auto; padding: 1.25rem; position: relative; z-index: 1; }
@media (max-width: 768px) { .main { padding: 0.85rem; } }
</style>
