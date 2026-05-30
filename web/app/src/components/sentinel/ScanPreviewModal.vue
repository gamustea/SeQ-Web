<template>
  <div v-if="show" class="modal visible" role="dialog" aria-modal="true">
    <div class="modal-backdrop" @click="$emit('close')"></div>
    <div class="modal-content preview-modal">
      <div class="modal-header">
        <h2>{{ typeLabel }}</h2>
        <button class="modal-close" @click="$emit('close')" aria-label="Cerrar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>

      <div class="modal-body" v-if="scan">
        <!-- Info Card -->
        <div class="pv-card pv-info-card">
          <div class="pv-card-top">
            <span class="pv-badge">#{{ scan.id }}</span>
            <span class="pv-type-tag">{{ type.toUpperCase() }}</span>
          </div>
          <div class="pv-target-row">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="pv-icon"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>
            <span class="pv-target">{{ scan.target }}</span>
          </div>
          <div class="pv-meta">
            <StatusBadge :status="scan.status" />
            <span class="pv-sep">&middot;</span>
            <span class="pv-date">Iniciado {{ fmt(scan.startedAt) }}</span>
            <span class="pv-sep">&middot;</span>
            <span class="pv-date">Finalizado {{ fmt(scan.finishedAt) || 'En curso' }}</span>
          </div>
        </div>

        <!-- Stats Card -->
        <div class="pv-card pv-stats-card">
          <div class="pv-stats-row">
            <template v-if="type === 'nmap'">
              <div class="pv-stat">
                <span class="pv-stat-val">{{ scan.totalOpenPorts ?? 0 }}</span>
                <span class="pv-stat-lbl">Puertos Abiertos</span>
              </div>
            </template>
            <template v-if="type === 'nikto'">
              <div class="pv-stat">
                <span class="pv-stat-val">{{ scan.totalIncidents ?? 0 }}</span>
                <span class="pv-stat-lbl">Incidencias</span>
              </div>
            </template>
            <template v-if="type === 'openvas'">
              <div class="pv-stat crit">
                <span class="pv-stat-val">{{ scan.criticalCount ?? 0 }}</span>
                <span class="pv-stat-lbl">Cr&iacute;ticas</span>
              </div>
              <div class="pv-stat high">
                <span class="pv-stat-val">{{ scan.highCount ?? 0 }}</span>
                <span class="pv-stat-lbl">Altas</span>
              </div>
            </template>
          </div>
        </div>

        <!-- Documents Card -->
        <div class="pv-card pv-docs-card">
          <div class="pv-docs-head">
            <h4>Documentos <span class="pv-count">{{ docs.length }}</span></h4>
            <button class="pv-refresh-btn" @click="$emit('refresh-docs')" :disabled="docsLoading" title="Refrescar">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: docsLoading }"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            </button>
          </div>

          <div v-if="docsLoading" class="pv-empty">Cargando documentos&hellip;</div>
          <div v-else-if="!docs.length" class="pv-empty">Sin documentos generados</div>
          <div v-else class="pv-docs-list">
            <div v-for="doc in docs" :key="doc.documentId" class="pv-doc-item">
              <div class="pv-doc-left">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="pv-doc-icon"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                <span class="pv-doc-name">
                  PDF {{ doc.scanType?.toUpperCase() }}
                  <span v-if="doc.isAiGenerated" class="pv-ai-pill">IA</span>
                </span>
                <span v-if="doc.createdAt" class="pv-doc-date">{{ fmtDate(doc.createdAt) }}</span>
              </div>
              <div class="pv-doc-right">
                <template v-if="doc.status === 'done'">
                  <button class="pv-icon-btn" @click="$emit('download-doc', doc.documentId)" title="Descargar">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  </button>
                  <button class="pv-icon-btn danger" @click="$emit('delete-doc', doc.documentId)" title="Eliminar">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                  </button>
                </template>
                <span v-else-if="doc.status === 'running'" class="pv-doc-status running">Generando&hellip;</span>
                <span v-else-if="doc.status === 'pending'" class="pv-doc-status pending">Pendiente</span>
                <span v-else-if="doc.status === 'error'" class="pv-doc-status error">Error</span>
              </div>
            </div>
          </div>

          <div class="pv-gen-bar">
            <label class="pv-checkbox">
              <input type="checkbox" v-model="useAi" />
              <span>An&aacute;lisis IA con Ollama</span>
            </label>
            <button class="pv-gen-btn" @click="$emit('generate-pdf', scan.id, type, useAi)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="pv-gen-icon"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
              Generar PDF
            </button>
          </div>
        </div>
      </div>

      <div class="modal-body empty-state" v-else-if="!scan">
        <svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:24px"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
        <span>Cargando&hellip;</span>
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

defineEmits(['close', 'refresh-docs', 'download-doc', 'delete-doc', 'generate-pdf'])

const useAi = ref(false)
const typeLabels = { nmap: 'Vista Previa \u2014 Nmap', nikto: 'Vista Previa \u2014 Nikto', openvas: 'Vista Previa \u2014 OpenVAS' }
const typeLabel = computed(() => typeLabels[props.type] || '')

function fmt(iso) { if (!iso || iso === 'null') return 'N/A'; return new Date(iso).toLocaleString() }
function fmtDate(iso) { if (!iso) return ''; return new Date(iso).toLocaleDateString() }
</script>

<style scoped>
.preview-modal { max-width: 520px; }

/* ── Cards ── */
.pv-card {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1rem;
  margin-bottom: 0.75rem;
}

/* ── Info Card ── */
.pv-info-card { border-left: 3px solid var(--accent); }
.pv-card-top { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.6rem; }
.pv-badge {
  font-family: var(--font-mono); font-size: 0.85rem; font-weight: 800;
  color: var(--accent); background: var(--accent-dim);
  padding: 3px 10px; border-radius: 6px; letter-spacing: 0.02em;
}
.pv-type-tag {
  font-size: 0.62rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--text-muted); background: var(--surface-3); padding: 3px 8px; border-radius: 4px;
}
.pv-target-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.55rem; }
.pv-icon { width: 16px; height: 16px; color: var(--accent); flex-shrink: 0; }
.pv-target { font-size: 0.88rem; color: var(--text); font-family: var(--font-mono); word-break: break-all; }
.pv-meta { display: flex; align-items: center; gap: 0.4rem; font-size: 0.72rem; color: var(--text-muted); flex-wrap: wrap; }
.pv-sep { color: var(--border-med); font-weight: 300; }
.pv-date { color: var(--text-muted); }

/* ── Stats Card ── */
.pv-stats-row { display: flex; gap: 0.5rem; }
.pv-stat {
  flex: 1; text-align: center; padding: 0.65rem 0.35rem;
  background: var(--surface); border-radius: 6px;
  border: 1px solid transparent; transition: border-color var(--transition);
}
.pv-stat.crit { background: rgba(248,113,113,0.08); border-color: rgba(248,113,113,0.2); }
.pv-stat.high { background: rgba(251,191,36,0.08); border-color: rgba(251,191,36,0.2); }
.pv-stat-val { display: block; font-family: var(--font-mono); font-size: 1.5rem; font-weight: 800; color: var(--text); line-height: 1.2; }
.pv-stat.crit .pv-stat-val { color: var(--danger); }
.pv-stat.high .pv-stat-val { color: var(--warn); }
.pv-stat-lbl { font-size: 0.62rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 2px; display: block; }

/* ── Docs Card ── */
.pv-docs-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem; }
.pv-docs-head h4 { font-size: 0.88rem; color: var(--text); font-weight: 600; display: flex; align-items: center; gap: 0.4rem; }
.pv-count {
  font-size: 0.68rem; font-weight: 500; color: var(--text-muted);
  background: var(--surface-3); padding: 1px 7px; border-radius: 10px;
}
.pv-refresh-btn {
  background: none; border: none; color: var(--text-muted); cursor: pointer;
  padding: 4px; border-radius: 6px; display: flex;
}
.pv-refresh-btn:hover:not(:disabled) { color: var(--accent); }
.pv-refresh-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.pv-refresh-btn svg { width: 14px; height: 14px; }

.pv-empty { font-size: 0.82rem; color: var(--text-muted); padding: 1rem 0; text-align: center; }

.pv-docs-list { display: flex; flex-direction: column; gap: 0.4rem; margin-bottom: 0.75rem; max-height: 220px; overflow-y: auto; }
.pv-doc-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0.5rem 0.7rem; background: var(--surface);
  border: 1px solid var(--border); border-radius: 7px;
  transition: border-color var(--transition);
}
.pv-doc-item:hover { border-color: var(--accent); }
.pv-doc-left { display: flex; align-items: center; gap: 0.5rem; min-width: 0; flex: 1; }
.pv-doc-icon { width: 16px; height: 16px; color: var(--text-muted); flex-shrink: 0; }
.pv-doc-name { font-size: 0.8rem; color: var(--text); font-weight: 500; white-space: nowrap; }
.pv-ai-pill { font-size: 0.6rem; color: var(--accent); background: var(--accent-dim); padding: 1px 5px; border-radius: 3px; margin-left: 4px; font-weight: 700; }
.pv-doc-date { font-size: 0.7rem; color: var(--text-muted); white-space: nowrap; }
.pv-doc-right { display: flex; gap: 0.25rem; align-items: center; flex-shrink: 0; }

.pv-icon-btn {
  width: 28px; height: 28px; display: flex; align-items: center; justify-content: center;
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 5px;
  color: var(--text-muted); cursor: pointer; transition: all var(--transition);
}
.pv-icon-btn:hover { border-color: var(--accent); color: var(--accent); }
.pv-icon-btn.danger:hover { border-color: var(--danger); color: var(--danger); background: var(--danger-dim); }
.pv-icon-btn svg { width: 14px; height: 14px; }

.pv-doc-status { font-size: 0.66rem; padding: 3px 9px; border-radius: 10px; font-weight: 600; white-space: nowrap; text-transform: uppercase; letter-spacing: 0.03em; }
.pv-doc-status.running { background: var(--info-dim); color: var(--info); }
.pv-doc-status.pending { background: var(--warn-dim); color: var(--warn); }
.pv-doc-status.error   { background: var(--danger-dim); color: var(--danger); }

/* ── Generate Bar ── */
.pv-gen-bar {
  display: flex; align-items: center; justify-content: space-between;
  padding-top: 0.75rem; border-top: 1px solid var(--border);
}
.pv-checkbox { display: flex; align-items: center; gap: 0.4rem; font-size: 0.78rem; color: var(--text-dim); cursor: pointer; user-select: none; }
.pv-checkbox input[type="checkbox"] { accent-color: var(--accent); width: 15px; height: 15px; cursor: pointer; }
.pv-gen-btn {
  display: flex; align-items: center; gap: 0.4rem;
  padding: 0.45rem 0.85rem; font-size: 0.78rem; font-weight: 600;
  background: var(--accent-dim); border: 1px solid var(--accent);
  border-radius: 6px; color: var(--accent); cursor: pointer;
  transition: all var(--transition);
}
.pv-gen-btn:hover { background: var(--accent); color: #000; }
.pv-gen-icon { width: 13px; height: 13px; }

/* ── Shared ── */
.spin { animation: seq-spin 0.8s linear infinite; }

@media (max-width: 560px) {
  .pv-stats-row { flex-direction: column; gap: 0.35rem; }
  .pv-gen-bar { flex-direction: column; align-items: stretch; gap: 0.5rem; }
  .pv-gen-btn { justify-content: center; }
}
</style>
