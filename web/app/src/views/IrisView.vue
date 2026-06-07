<template>
  <div class="iris-page" data-module="iris">
    <StarBackground />
    <Topbar title="Iris" badge="Análisis de Cabeceras" />

    <div class="iris-layout">
      <IrisHistoryStrip
        :items="sortedAnalyses"
        :active-id="store.currentId"
        :sort="sortMode"
        @select="store.selectAnalysis"
        @sort="handleSort"
        @delete="handleDelete"
      />

      <main class="iris-main">
        <IrisReportViewer
          :report-id="store.currentId"
          :report-data="store.currentReport.data"
          :report-loading="store.currentReport.loading"
          :status="store.currentStatus.status"
          :progress="store.currentStatus.progress"
          @cancel="handleCancel"
          @delete="handleDelete"
        >
          <template #form>
            <IrisForm
              :key="formKey"
              :submitting="store.submitting"
              @submit="handleSubmit"
            />
          </template>
        </IrisReportViewer>
      </main>
    </div>

    <AppToast />
  </div>
</template>

<script setup>
import { onMounted, computed, ref } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import IrisHistoryStrip from '@/components/iris/IrisHistoryStrip.vue'
import IrisReportViewer from '@/components/iris/IrisReportViewer.vue'
import IrisForm from '@/components/iris/IrisForm.vue'
import { useIrisStore } from '@/stores/irisStore'

const store = useIrisStore()
const formKey = ref(0)

const sortMode = computed({
  get: () => store.sortMode || 'date-desc',
  set: (v) => { store.sortMode = v },
})

const sortedAnalyses = computed(() => {
  const items = [...store.analyses]
  switch (sortMode.value) {
    case 'date-asc':
      return items.sort((a, b) => new Date(a.startedAt || 0) - new Date(b.startedAt || 0))
    case 'score-desc':
      return items.sort((a, b) => (b.totalScore ?? -999) - (a.totalScore ?? -999))
    case 'score-asc':
      return items.sort((a, b) => (a.totalScore ?? -999) - (b.totalScore ?? -999))
    default:
      return items.sort((a, b) => new Date(b.startedAt || 0) - new Date(a.startedAt || 0))
  }
})

onMounted(async () => {
  await store.fetchResults()
  const last = store.analyses[0]
  if (last && (last.status === 'running' || last.status === 'pending')) {
    store.selectAnalysis(last.analysisId)
  }
})

async function handleSubmit({ headers, title }) {
  const id = await store.submitAnalysis(headers, title)
  if (id) formKey.value++
}

async function handleCancel() {
  if (store.currentId) {
    await store.cancelAnalysis(store.currentId)
  }
}

async function handleDelete(id) {
  await store.deleteAnalysis(id)
}

function handleSort(mode) {
  sortMode.value = mode
}
</script>

<style scoped>
.iris-page {
  min-height: 100vh;
  background: var(--bg);
  padding-top: var(--topbar-h);
  position: relative;
}

.iris-layout {
  display: flex;
  flex-direction: column;
  height: calc(100vh - var(--topbar-h));
  position: relative;
  z-index: 1;
}

.iris-main {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}
</style>
