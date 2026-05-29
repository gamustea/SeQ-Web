<template>
  <div class="aegis-page">
    <Topbar title="Aegis" badge="Generación de Píldoras" />

    <div class="app-layout">
      <!-- Left panel: Generation form -->
      <aside class="panel panel--left">
        <TweaksForm />
      </aside>

      <!-- Center: Document viewer -->
      <section class="panel panel--center">
        <DocumentViewer
          :viewer-doc="store.viewerDoc"
          @close="store.closeViewer()"
          @export="(fmt) => store.downloadExport(store.currentDocId, fmt)"
          @preview="() => store.previewMarkdown(store.currentDocId)"
        />
      </section>

      <!-- Right: History -->
      <aside class="panel panel--right">
        <HistoryPanel
          :documents="store.sortedDocuments()"
          :current-doc-id="store.currentDocId"
          :sort-mode="store.sortMode"
          @view="store.loadDocument($event)"
          @delete="store.deleteDocument($event)"
          @export="(docId, fmt) => store.downloadExport(docId, fmt)"
          @preview="store.previewMarkdown($event)"
          @sort="store.sortMode = $event"
          @refresh="store.loadHistory()"
        />
      </aside>
    </div>

    <StarBackground />
    <AppToast />
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import { useAegisStore } from '@/stores/aegisStore'
import TweaksForm from '@/components/aegis/TweaksForm.vue'
import DocumentViewer from '@/components/aegis/DocumentViewer.vue'
import HistoryPanel from '@/components/aegis/HistoryPanel.vue'

const store = useAegisStore()

onMounted(async () => {
  await Promise.all([store.loadTopics(), store.loadBrands()])
  await store.loadHistory()
})
</script>

<style scoped>
.aegis-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); }

.app-layout {
  display: grid;
  grid-template-columns: 380px 1fr 360px;
  gap: 0;
  height: calc(100vh - var(--topbar-h));
  overflow: hidden;
}

.panel { overflow-y: auto; }

.panel--left   { background: var(--surface); border-right: 1px solid var(--border); }
.panel--center { background: var(--bg); }
.panel--right  { background: var(--bg); border-left: 1px solid var(--border); }

@media (max-width: 1100px) {
  .app-layout { grid-template-columns: 1fr; grid-template-rows: auto 1fr auto; }
  .panel--left, .panel--right { border: none; border-bottom: 1px solid var(--border); max-height: 45vh; }
}
</style>
