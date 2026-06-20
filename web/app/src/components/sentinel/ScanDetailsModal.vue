<template>
  <div v-if="show" class="modal visible" role="dialog" aria-modal="true">
    <div class="modal-backdrop" @click="$emit('close')"></div>
    <div class="modal-content scan-details-modal">
      <div class="modal-header">
        <h2>Detalles del Escaneo — {{ type.toUpperCase() }}</h2>
        <button class="modal-close" @click="$emit('close')" aria-label="Cerrar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
      <div class="modal-body" v-if="scan">
        <div class="detail-section">
          <h3>Información General</h3>
          <div class="detail-grid">
            <span class="dl">ID:</span><span class="dv mono">#{{ scan.id }}</span>
            <span class="dl">Target:</span><span class="dv">{{ scan.target }}</span>
            <span class="dl">Estado:</span><span class="dv"><StatusBadge :status="scan.status" /></span>
            <span class="dl">Iniciado:</span><span class="dv">{{ fmt(scan.startedAt) }}</span>
            <span class="dl">Finalizado:</span><span class="dv">{{ fmt(scan.finishedAt) }}</span>
          </div>
        </div>
        <div v-if="type === 'nmap' && scan.openPorts?.length" class="detail-section">
          <h3>Puertos Abiertos ({{ scan.openPorts.length }})</h3>
          <table class="ports-table">
            <thead><tr><th>Puerto</th><th>Protocolo</th><th>Servicio</th><th>Versión</th></tr></thead>
            <tbody>
              <tr v-for="p in scan.openPorts" :key="p.port">
                <td class="mono">{{ p.port }}</td>
                <td class="mono">{{ p.port?.split('/')[1] ?? '-' }}</td>
                <td>{{ p.product ?? '-' }}</td>
                <td>{{ p.product ?? '-' }}{{ p.version ? ' ' + p.version : '' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-if="type === 'nikto' && scan.incidents?.length" class="detail-section">
          <h3>Incidencias ({{ scan.incidents.length }})</h3>
          <div class="vulns-scroll">
            <div v-for="inc in scan.incidents" :key="inc.id" class="incident-card">
              <div class="incident-header">
                <span class="incident-title">{{ inc.method ?? 'GET' }} {{ inc.url ?? '' }}</span>
                <span class="severity-badge" :class="sevClass(inc.severity)">{{ inc.severity ?? 'MEDIUM' }}</span>
              </div>
              <div class="incident-desc">{{ inc.description }}</div>
            </div>
          </div>
        </div>
        <div v-if="type === 'openvas' && scan.vulnerabilities?.length" class="detail-section">
          <h3>Vulnerabilidades ({{ scan.vulnerabilities.length }})</h3>
          <div class="vulns-scroll">
            <div v-for="v in scan.vulnerabilities" :key="v.id" class="incident-card">
              <div class="incident-header">
                <span class="incident-title">{{ v.name }}</span>
                <span class="severity-badge" :class="sevClass(v.severityClass)">{{ v.severityClass ?? 'Unknown' }}</span>
              </div>
              <div class="incident-desc">{{ v.description }}</div>
            </div>
          </div>
        </div>
        <div class="detail-section" v-if="!hasDetailData">
          <div class="empty-state">No hay datos disponibles.</div>
        </div>
        <div class="detail-section document-section">
          <div class="docs-header">
            <div class="docs-title-wrap">
              <h3>Documentos ({{ docs.length }})</h3>
              <button class="docs-refresh" @click="$emit('refresh-docs')" :disabled="docsLoading">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: docsLoading }"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
              </button>
            </div>
            <label class="doc-checkbox"><input type="checkbox" v-model="useAiDocs" /><span class="doc-checklabel">Análisis IA con Ollama</span></label>
            <button class="docs-gen-btn" @click="$emit('generate-pdf', scan.id, type, useAiDocs)">Generar PDF</button>
          </div>
          <div v-if="docsLoading" class="docs-empty">Cargando documentos…</div>
          <div v-else-if="!docs.length" class="docs-empty">Sin documentos generados</div>
          <div v-else class="docs-list">
            <div v-for="doc in docs" :key="doc.documentId" class="doc-item">
              <div class="doc-info">
                <span class="doc-name">PDF {{ doc.scanType?.toUpperCase() }} <span v-if="doc.isAiGenerated" class="doc-ai-badge">IA</span></span>
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
        </div>
      </div>
      <div class="modal-body empty-state" v-else>
        <svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:22px"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
        <span>Cargando…</span>
      </div>
      <div class="modal-footer">
        <button class="btn btn--secondary" @click="$emit('close')">Cerrar</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import StatusBadge from './StatusBadge.vue'

const props = defineProps({ show: Boolean, scan: Object, type: String, docs: { type: Array, default: () => [] }, docsLoading: Boolean })
defineEmits(['close', 'refresh-docs', 'download-doc', 'delete-doc', 'generate-pdf'])
const useAiDocs = ref(false)

const hasDetailData = computed(() => {
  if (!props.scan) return false
  if (props.type === 'nmap') return props.scan.openPorts?.length
  if (props.type === 'nikto') return props.scan.incidents?.length
  if (props.type === 'openvas') return props.scan.vulnerabilities?.length
  return false
})

function fmt(iso) { if (!iso || iso === 'null') return 'N/A'; return new Date(iso).toLocaleString() }
function fmtDate(iso) { if (!iso) return ''; return new Date(iso).toLocaleDateString() }
function sevClass(s) { if (!s) return 'low'; const x = s.toLowerCase(); if (x.includes('crit')) return 'critical'; if (x.includes('high')) return 'high'; if (x.includes('med')) return 'medium'; return 'low' }
</script>

<style scoped>
.detail-section { margin-bottom: 1.25rem; }
.detail-section h3 { font-size: 0.9rem; font-weight: 600; color: var(--text); margin-bottom: 0.65rem; font-family: var(--font-display); }
.detail-grid { display: grid; grid-template-columns: auto 1fr; gap: 0.3rem 0.85rem; padding: 0.65rem; background: var(--surface-2); border-radius: 8px; }
.dl { font-size: 0.72rem; color: var(--text-muted); font-weight: 500; }
.dv { font-size: 0.82rem; color: var(--text); }
.mono { font-family: var(--font-mono); font-size: 0.78rem; }
.ports-table { width: 100%; border-collapse: collapse; margin-top: 0.4rem; }
.ports-table th { text-align: left; padding: 0.4rem 0.6rem; font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; background: var(--surface-2); }
.ports-table td { padding: 0.4rem 0.6rem; font-size: 0.8rem; border-top: 1px solid var(--border); color: var(--text); }
.vulns-scroll { max-height: 320px; overflow-y: auto; }
.incident-card { padding: 0.6rem 0.75rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 7px; margin-bottom: 0.4rem; }
.incident-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.25rem; }
.incident-title { font-size: 0.8rem; font-weight: 600; color: var(--text); word-break: break-all; margin-right: 0.4rem; flex: 1; }
.incident-desc { font-size: 0.75rem; color: var(--text-dim); line-height: 1.5; }
.severity-badge { font-size: 0.62rem; padding: 2px 6px; border-radius: 8px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.03em; white-space: nowrap; }
.severity-badge.critical { background: rgba(217,108,108,0.15); color: var(--danger); border: 1px solid rgba(217,108,108,0.25); }
.severity-badge.high { background: rgba(212,160,74,0.12); color: var(--warn); border: 1px solid rgba(212,160,74,0.2); }
.severity-badge.medium { background: rgba(96,128,224,0.12); color: var(--info); border: 1px solid rgba(96,128,224,0.2); }
.severity-badge.low { background: var(--surface-3); color: var(--text-muted); border: 1px solid var(--border); }
.document-section { border-top: 1px solid var(--border); padding-top: 0.85rem; }
.docs-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.65rem; }
.docs-title-wrap { display: flex; align-items: center; gap: 0.4rem; }
.docs-refresh { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 3px; border-radius: 5px; }
.docs-refresh:hover { color: var(--accent); }
.docs-refresh svg { width: 13px; height: 13px; }
.spin { animation: seq-spin 0.8s linear infinite; }
.doc-checkbox { display: flex; align-items: center; gap: 0.35rem; font-size: 0.78rem; color: var(--text-dim); cursor: pointer; }
.doc-checklabel { user-select: none; }
.docs-gen-btn { padding: 0.3rem 0.7rem; font-size: 0.75rem; background: var(--accent-dim); border: 1px solid var(--accent); border-radius: 6px; color: var(--accent-bright); cursor: pointer; font-weight: 500; }
.docs-gen-btn:hover { background: var(--accent); color: #0b0c10; }
.docs-empty { font-size: 0.8rem; color: var(--text-muted); padding: 0.85rem 0; text-align: center; }
.docs-list { display: flex; flex-direction: column; gap: 0.35rem; }
.doc-item { display: flex; align-items: center; justify-content: space-between; padding: 0.4rem 0.55rem; background: var(--surface-2); border-radius: 6px; }
.doc-info { display: flex; align-items: center; gap: 0.45rem; }
.doc-name { font-size: 0.8rem; color: var(--text); font-weight: 500; }
.doc-ai-badge { font-size: 0.62rem; color: var(--accent); background: var(--accent-dim); padding: 1px 4px; border-radius: 3px; margin-left: 3px; }
.doc-date { font-size: 0.68rem; color: var(--text-muted); }
.doc-actions { display: flex; gap: 0.2rem; }
.doc-btn { width: 26px; height: 26px; display: flex; align-items: center; justify-content: center; background: var(--surface); border: 1px solid var(--border); border-radius: 5px; color: var(--text-muted); cursor: pointer; }
.doc-btn:hover { border-color: var(--accent); color: var(--accent); }
.doc-btn.danger:hover { border-color: var(--danger); color: var(--danger); }
.doc-btn svg { width: 12px; height: 12px; }
.doc-status { font-size: 0.7rem; padding: 2px 7px; border-radius: 8px; }
.doc-status.pending { background: var(--warn-dim); color: var(--warn); }
.doc-status.error { background: var(--danger-dim); color: var(--danger); }
.empty-state { display: flex; flex-direction: column; align-items: center; gap: 0.4rem; padding: 1.5rem 1rem; color: var(--text-muted); font-size: 0.82rem; }
</style>
