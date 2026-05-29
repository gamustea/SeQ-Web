<template>
  <div class="viewer">
    <!-- Empty -->
    <div v-if="!viewerDoc.data && !viewerDoc.loading" class="viewer-empty">
      <div class="empty-icon">&#128218;</div>
      <h3>Visor de Documentos</h3>
      <p>Selecciona un documento del historial o genera una nueva píldora para ver su contenido aquí.</p>
    </div>

    <!-- Loading -->
    <div v-else-if="viewerDoc.loading" class="viewer-loading">
      <div class="spinner-lg"></div>
      <p>Cargando documento…</p>
    </div>

    <!-- Document -->
    <div v-else-if="viewerDoc.data" class="viewer-content">
      <div class="viewer-toolbar">
        <span class="doc-id">Doc #{{ viewerDoc.data.id }}</span>
        <span v-if="viewerDoc.data.topicId" class="doc-topic">Tema #{{ viewerDoc.data.topicId }}</span>
        <span class="doc-date">{{ formatDate(viewerDoc.data.generatedAt) }}</span>
        <div class="toolbar-spacer"></div>
        <div class="export-dropdown">
          <button type="button" class="toolbar-btn" @click="exportOpen = !exportOpen">Exportar</button>
          <div v-if="exportOpen" class="export-menu">
            <button @click="emitExport('md')">Markdown</button>
            <button @click="emitExport('html')">HTML</button>
            <button @click="emitExport('json')">JSON</button>
          </div>
        </div>
        <button type="button" class="toolbar-btn" @click="emit('preview')">Vista previa</button>
        <button type="button" class="toolbar-btn toolbar-close" @click="emit('close')">&times;</button>
      </div>

      <div class="pill-body">
        <h2 class="pill-title">{{ viewerDoc.data.title }}</h2>
        <p class="pill-subtitle" v-if="viewerDoc.data.subtitle">{{ viewerDoc.data.subtitle }}</p>

        <section v-if="viewerDoc.data.pill?.intro" class="pill-section">
          <p class="pill-intro">{{ viewerDoc.data.pill.intro }}</p>
        </section>

        <section v-if="viewerDoc.data.pill?.tips?.length" class="pill-section">
          <h3>Recomendaciones</h3>
          <div v-for="(tip, i) in viewerDoc.data.pill.tips" :key="i" class="pill-tip">
            <span class="tip-num">{{ i + 1 }}</span>
            <div class="tip-body">
              <h4>{{ tip.headline }}</h4>
              <p>{{ tip.body }}</p>
              <div v-if="tip.links?.length" class="tip-links">
                <a v-for="(link, j) in tip.links" :key="j" :href="link.url" target="_blank" rel="noopener" class="tip-link">{{ link.text }}</a>
              </div>
            </div>
          </div>
        </section>

        <section v-if="viewerDoc.data.pill?.closing" class="pill-section">
          <p class="pill-closing">{{ viewerDoc.data.pill.closing }}</p>
        </section>

        <section v-if="viewerDoc.data.alerts?.length" class="pill-section">
          <h3>Alertas de Seguridad</h3>
          <div v-for="(alert, i) in viewerDoc.data.alerts" :key="i" class="pill-alert" :class="`pill-alert--${alert.severity || 'informativa'}`">
            <div class="alert-header">
              <span class="alert-severity">{{ sevIcon(alert.severity) }}</span>
              <a v-if="alert.url" :href="alert.url" target="_blank" rel="noopener" class="alert-title">{{ alert.title }}</a>
              <span v-else class="alert-title">{{ alert.title }}</span>
            </div>
            <p class="alert-desc" v-if="alert.description">{{ alert.description }}</p>
            <div class="alert-meta" v-if="alert.source || alert.sourceLabel">
              <span class="alert-source">{{ alert.sourceLabel || alert.source }}</span>
              <span v-if="alert.published" class="alert-published">{{ formatDate(alert.published) }}</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useUtils } from '@/composables/useUtils'

const { formatDate } = useUtils()

defineProps({
  viewerDoc: { type: Object, default: () => ({ loading: false, data: null }) },
})

const emit = defineEmits(['close', 'export', 'preview'])
const exportOpen = ref(false)

const sevIcons = { critica: '🔴', alta: '🟠', media: '🟡', baja: '🟢', informativa: '🔵' }
function sevIcon(sev) { return sevIcons[sev] || sevIcons.informativa }
function emitExport(fmt) { exportOpen.value = false; emit('export', fmt) }
</script>

<style scoped>
.viewer { min-height: 100%; display: flex; flex-direction: column; }

.viewer-empty { text-align: center; padding: 3rem 1.5rem; color: var(--text-muted); }
.empty-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
.viewer-empty h3 { font-size: 1.1rem; font-weight: 600; color: var(--text-dim); margin: 0 0 0.5rem; }
.viewer-empty p { font-size: 0.82rem; line-height: 1.5; max-width: 320px; margin: 0 auto; }

.viewer-loading { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 1rem; padding: 4rem 0; color: var(--text-muted); font-size: 0.85rem; }
.spinner-lg { width: 36px; height: 36px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

.viewer-content { flex: 1; display: flex; flex-direction: column; }

.viewer-toolbar {
  display: flex; align-items: center; gap: 0.5rem; padding: 0.6rem 1rem;
  background: var(--surface); border-bottom: 1px solid var(--border);
  font-size: 0.76rem; color: var(--text-muted); flex-wrap: wrap;
}
.doc-id, .doc-topic { font-weight: 600; color: var(--text-dim); font-family: var(--font-mono); }
.toolbar-spacer { flex: 1; }

.toolbar-btn {
  padding: 0.3rem 0.7rem; font-size: 0.7rem; font-weight: 600; border-radius: 5px;
  border: 1px solid var(--border); background: var(--bg); color: var(--text-dim); cursor: pointer; transition: background 0.2s;
}
.toolbar-btn:hover { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.toolbar-close { border: none; background: none; font-size: 1.2rem; padding: 0 0.3rem; line-height: 1; }
.toolbar-close:hover { background: none; color: var(--danger); }

.export-dropdown { position: relative; }
.export-menu {
  position: absolute; right: 0; top: 100%; margin-top: 4px; z-index: 20;
  background: var(--surface); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; min-width: 110px;
}
.export-menu button {
  display: block; width: 100%; text-align: left; padding: 0.4rem 0.7rem;
  font-size: 0.75rem; background: none; border: none; color: var(--text-dim); cursor: pointer; transition: background 0.15s;
}
.export-menu button:hover { background: var(--accent); color: var(--bg); }

.pill-body { padding: 1.5rem; overflow-y: auto; flex: 1; }
.pill-title { font-size: 1.4rem; font-weight: 800; color: var(--text); margin: 0 0 0.25rem; }
.pill-subtitle { font-size: 0.9rem; color: var(--text-dim); margin: 0 0 1.5rem; }

.pill-section { margin-bottom: 1.5rem; }
.pill-section h3 { font-size: 1rem; font-weight: 700; color: var(--accent); margin: 0 0 0.75rem; padding-bottom: 0.35rem; border-bottom: 1px solid var(--border); }

.pill-intro, .pill-closing { font-size: 0.88rem; line-height: 1.65; color: var(--text); }

.pill-tip { display: flex; gap: 0.75rem; margin-bottom: 1rem; }
.tip-num {
  width: 26px; height: 26px; border-radius: 50%; flex-shrink: 0;
  background: var(--accent); color: var(--bg); font-size: 0.75rem; font-weight: 700;
  display: flex; align-items: center; justify-content: center;
}
.tip-body { flex: 1; min-width: 0; }
.tip-body h4 { font-size: 0.92rem; font-weight: 700; color: var(--text); margin: 0 0 0.2rem; }
.tip-body p { font-size: 0.82rem; line-height: 1.5; color: var(--text-dim); margin: 0 0 0.35rem; }
.tip-links { display: flex; gap: 0.5rem; flex-wrap: wrap; }
.tip-link { font-size: 0.75rem; color: var(--accent); text-decoration: none; font-weight: 600; }
.tip-link:hover { text-decoration: underline; }

.pill-alert { padding: 0.75rem; border-radius: 8px; margin-bottom: 0.6rem; border: 1px solid var(--border); background: var(--bg); }
.pill-alert--critica     { border-color: rgba(239,68,68,0.25); border-left: 3px solid var(--danger); }
.pill-alert--alta        { border-color: rgba(251,146,60,0.2); border-left: 3px solid #fb923c; }
.pill-alert--media       { border-color: rgba(251,191,36,0.2); border-left: 3px solid var(--warn); }
.pill-alert--baja        { border-color: rgba(52,211,153,0.2); border-left: 3px solid var(--success); }
.pill-alert--informativa { border-color: rgba(96,165,250,0.2); border-left: 3px solid var(--info); }

.alert-header { display: flex; align-items: center; gap: 0.4rem; margin-bottom: 0.25rem; }
.alert-severity { font-size: 0.85rem; }
.alert-title { font-size: 0.85rem; font-weight: 700; color: var(--text); text-decoration: none; }
a.alert-title:hover { color: var(--accent); text-decoration: underline; }
.alert-desc { font-size: 0.78rem; color: var(--text-dim); margin: 0.25rem 0; line-height: 1.45; }
.alert-meta { display: flex; gap: 0.75rem; font-size: 0.7rem; color: var(--text-muted); margin-top: 0.35rem; }
</style>
