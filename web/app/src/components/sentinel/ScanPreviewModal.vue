<template>
  <div v-if="show" class="modal visible" role="dialog" aria-modal="true">
    <div class="modal-backdrop" @click="$emit('close')"></div>
    <div class="modal-content scan-preview-modal">
      <div class="modal-header">
        <h2>{{ typeLabel }}</h2>
        <button class="modal-close" @click="$emit('close')" aria-label="Cerrar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>

      <div class="modal-body" v-if="scan">
        <div class="preview-header">
          <span class="preview-header-type">{{ typeLabel }}</span>
          <div class="preview-header-id">Escaneo #{{ scan.id }}</div>
        </div>

        <div class="preview-meta">
          <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">{{ scan.target }}</span></div>
          <div class="meta-item"><span class="meta-label">Estado</span><span class="meta-value"><StatusBadge :status="scan.status" /></span></div>
          <div class="meta-item"><span class="meta-label">Iniciado</span><span class="meta-value">{{ fmt(scan.startedAt) }}</span></div>
          <div class="meta-item"><span class="meta-label">Finalizado</span><span class="meta-value">{{ fmt(scan.finishedAt) || 'En curso' }}</span></div>
        </div>

        <!-- Summary stats -->
        <div class="preview-summary">
          <template v-if="type === 'nmap'">
            <div class="sum-stat"><span class="sum-value">{{ scan.totalOpenPorts ?? 0 }}</span><span class="sum-label">Puertos Abiertos</span></div>
          </template>
          <template v-if="type === 'nikto'">
            <div class="sum-stat"><span class="sum-value">{{ scan.totalIncidents ?? 0 }}</span><span class="sum-label">Incidencias</span></div>
          </template>
          <template v-if="type === 'openvas'">
            <div class="sum-stat"><span class="sum-value">{{ scan.totalVulnerabilities ?? 0 }}</span><span class="sum-label">Vulnerabilidades</span></div>
            <div class="sum-stat crit"><span class="sum-value">{{ scan.criticalCount ?? 0 }}</span><span class="sum-label">Críticas</span></div>
            <div class="sum-stat high"><span class="sum-value">{{ scan.highCount ?? 0 }}</span><span class="sum-label">Altas</span></div>
          </template>
        </div>

        <!-- Actions -->
        <div class="preview-actions-row">
          <button class="preview-details-btn" @click="$emit('view-details', scan.id, type)">Ver detalles</button>
        </div>

        <!-- Documents -->
        <div class="preview-docs">
          <div class="docs-header">
            <h4>Documentos</h4>
            <button class="docs-refresh" @click="$emit('refresh-docs')" :disabled="docsLoading">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: docsLoading }"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            </button>
          </div>

          <div v-if="docsLoading" class="docs-empty">Cargando documentos…</div>
          <div v-else-if="!docs.length" class="docs-empty">Sin documentos generados</div>
          <div v-else class="docs-list">
            <div v-for="doc in docs" :key="doc.documentId" class="doc-item">
              <div class="doc-info">
                <span class="doc-name">PDF {{ doc.scanType?.toUpperCase() }}
                  <span v-if="doc.isAiGenerated" class="doc-ai-badge">IA</span>
                </span>
                <span v-if="doc.createdAt" class="doc-date">{{ fmtDate(doc.createdAt) }}</span>
              </div>
              <div class="doc-actions">
                <template v-if="doc.status === 'done'">
                  <button class="doc-btn" @click="$emit('download-doc', doc.documentId)" title="Descargar">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  </button>
                  <button class="doc-btn danger" @click="$emit('delete-doc', doc.documentId)" title="Eliminar">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                  </button>
                </template>
                <span v-else-if="doc.status === 'running'" class="doc-status pending">Generando…</span>
                <span v-else-if="doc.status === 'pending'" class="doc-status pending">Pendiente</span>
                <span v-else-if="doc.status === 'error'" class="doc-status error">Error</span>
              </div>
            </div>
          </div>

          <div class="docs-generate">
            <label class="doc-checkbox">
              <input type="checkbox" v-model="useAi" />
              <span class="doc-checklabel">Análisis IA con Ollama</span>
            </label>
            <button class="docs-gen-btn" @click="$emit('generate-pdf', scan.id, type, useAi)">Generar PDF</button>
          </div>
        </div>
      </div>

      <div class="modal-body empty-state" v-else-if="!scan">
        <svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:24px"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
        <span>Cargando…</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import StatusBadge from './StatusBadge.vue'

const props = defineProps({
  show: Boolean, scan: Object, type: String, docs: { type: Array, default: () => [] }, docsLoading: Boolean,
})

defineEmits(['close', 'view-details', 'refresh-docs', 'download-doc', 'delete-doc', 'generate-pdf'])

const useAi = ref(false)
const typeLabels = { nmap: 'Vista Previa — Nmap', nikto: 'Vista Previa — Nikto', openvas: 'Vista Previa — OpenVAS' }
const typeLabel = computed(() => typeLabels[props.type] || '')

function fmt(iso) { if (!iso || iso === 'null') return 'N/A'; return new Date(iso).toLocaleString() }
function fmtDate(iso) { if (!iso) return ''; return new Date(iso).toLocaleDateString() }
</script>

<style scoped>
.preview-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
.preview-header-type { font-weight: 600; font-size: 0.9rem; color: var(--accent); }
.preview-header-id { font-size: 0.78rem; color: var(--text-muted); font-family: var(--font-mono); }
.preview-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-bottom: 1rem; padding: 0.75rem; background: var(--surface-2); border-radius: 8px; }
.meta-item { display: flex; flex-direction: column; gap: 0.15rem; }
.meta-label { font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; }
.meta-value { font-size: 0.85rem; color: var(--text); }
.preview-summary { display: flex; gap: 1rem; margin-bottom: 1rem; }
.sum-stat { flex: 1; text-align: center; padding: 0.5rem; background: var(--surface-2); border-radius: 8px; }
.sum-value { font-size: 1.4rem; font-weight: 800; font-family: var(--font-mono); display: block; color: var(--text); }
.sum-label { font-size: 0.68rem; color: var(--text-muted); margin-top: 2px; }
.sum-stat.crit .sum-value { color: var(--danger); }
.sum-stat.high .sum-value { color: var(--warn); }
.preview-actions-row { margin-bottom: 1rem; }
.preview-details-btn { padding: 0.4rem 0.9rem; font-size: 0.8rem; background: var(--accent-dim); border: 1px solid var(--accent); border-radius: 7px; color: var(--accent); cursor: pointer; font-weight: 500; transition: all 0.2s; }
.preview-details-btn:hover { background: var(--accent); color: #000; }

.preview-docs { border-top: 1px solid var(--border); padding-top: 1rem; margin-top: 0.5rem; }
.docs-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; }
.docs-header h4 { font-size: 0.88rem; color: var(--text-dim); font-weight: 600; }
.docs-refresh { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 4px; border-radius: 6px; }
.docs-refresh:hover { color: var(--accent); }
.docs-refresh svg { width: 14px; height: 14px; }
.spin { animation: seq-spin 0.8s linear infinite; }
.docs-empty { font-size: 0.82rem; color: var(--text-muted); padding: 1rem 0; text-align: center; }
.docs-list { display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 0.75rem; max-height: 200px; overflow-y: auto; }
.doc-item { display: flex; align-items: center; justify-content: space-between; padding: 0.5rem 0.7rem; background: var(--surface-2); border-radius: 7px; }
.doc-info { display: flex; align-items: center; gap: 0.5rem; }
.doc-name { font-size: 0.82rem; color: var(--text); font-weight: 500; }
.doc-ai-badge { font-size: 0.65rem; color: var(--accent); background: var(--accent-dim); padding: 1px 5px; border-radius: 4px; margin-left: 4px; }
.doc-date { font-size: 0.7rem; color: var(--text-muted); }
.doc-actions { display: flex; gap: 0.25rem; }
.doc-btn { width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; background: var(--surface); border: 1px solid var(--border); border-radius: 5px; color: var(--text-muted); cursor: pointer; }
.doc-btn:hover { border-color: var(--accent); color: var(--accent); }
.doc-btn.danger:hover { border-color: var(--danger); color: var(--danger); }
.doc-btn svg { width: 13px; height: 13px; }
.doc-status { font-size: 0.72rem; padding: 2px 8px; border-radius: 10px; }
.doc-status.pending { background: var(--warn-dim); color: var(--warn); }
.doc-status.error { background: var(--danger-dim); color: var(--danger); }
.docs-generate { display: flex; align-items: center; gap: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--border); }
.doc-checkbox { display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; color: var(--text-dim); cursor: pointer; }
.doc-checklabel { user-select: none; }
.docs-gen-btn { padding: 0.4rem 0.9rem; font-size: 0.8rem; background: var(--accent-dim); border: 1px solid var(--accent); border-radius: 7px; color: var(--accent); cursor: pointer; font-weight: 500; transition: all 0.2s; }
.docs-gen-btn:hover { background: var(--accent); color: #000; }
</style>
