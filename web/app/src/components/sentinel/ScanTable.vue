<template>
  <div class="table-wrap">
    <div class="table-toolbar">
      <span class="toolbar-title">Resultados {{ type.toUpperCase() }}</span>
      <button class="btn-refresh" :disabled="loading" @click="$emit('refresh')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" :class="{ spin: loading }">
          <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
        </svg>
        Actualizar
      </button>
    </div>

    <!-- Loading -->
    <div v-if="showLoading" class="empty-state">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="spin"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
      <span>Cargando…</span>
    </div>

    <!-- Empty -->
    <div v-else-if="!rows.length" class="empty-state">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2">
        <rect x="2" y="3" width="20" height="14" rx="2"/>
        <line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
      </svg>
      <span>No hay escaneos todavía. ¡Lanza el primero!</span>
    </div>

    <!-- Table -->
    <template v-else>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Target</th>
            <th>Estado</th>
            <th v-if="type === 'nmap'">Puertos</th>
            <th v-if="type === 'nikto'">Incidencias</th>
            <template v-if="type === 'openvas'">
              <th>Vulns</th>
              <th>Críticas</th>
              <th>Altas</th>
            </template>
            <th>Fecha</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in rows" :key="row.id">
            <td class="mono">#{{ row.id }}</td>
            <td class="target">{{ row.target }}</td>
            <td><StatusBadge :status="row.status" /></td>
            <td v-if="type === 'nmap'" class="mono">{{ row.totalOpenPorts ?? 0 }} <span class="muted">puertos</span></td>
            <td v-if="type === 'nikto'" class="mono">{{ row.totalIncidents ?? 0 }} <span class="muted">hallazgos</span></td>
            <template v-if="type === 'openvas'">
              <td class="mono">{{ row.totalVulnerabilities ?? 0 }}</td>
              <td class="sev-critical"><span v-if="row.criticalCount">{{ row.criticalCount }}</span><span v-else class="muted">0</span></td>
              <td class="sev-high"><span v-if="row.highCount">{{ row.highCount }}</span><span v-else class="muted">0</span></td>
            </template>
            <td class="date">{{ formatDate(row.startedAt) }}</td>
            <td class="actions">
              <button class="act-btn" title="Vista previa" @click="$emit('preview', row.id, type)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
              <button v-if="isActive(row.status)" class="act-btn warn" title="Cancelar" @click="confirmCancel(row.id)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
              </button>
              <button class="act-btn danger" title="Eliminar" @click="confirmDelete(row.id)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4h6v2"/></svg>
              </button>
            </td>
          </tr>
        </tbody>
      </table>

    </template>

    <!-- Pagination -->
    <div class="table-footer">
      <AppPagination
        v-if="totalCount > perPage"
        :current="currentPage"
        :total="totalCount"
        :per-page="perPage"
        @go="page => $emit('page-change', page)"
      />
    </div>
  </div>
</template>

<script setup>
/**
 * ScanTable — Tabla de resultados de escaneo con paginacion.
 * Las columnas varian segun el tipo: nmap (puertos), nikto (incidencias), openvas (vulns).
 */
import { ref, watch, onUnmounted } from 'vue'
import StatusBadge from './StatusBadge.vue'
import AppPagination from '@/components/shared/AppPagination.vue'

const props = defineProps({
  type:    { type: String, required: true },
  rows:    { type: Array,  default: () => [] },
  loading: { type: Boolean, default: false },
  currentPage: { type: Number, default: 1 },
  totalCount:  { type: Number, default: 0 },
  perPage:     { type: Number, default: 10 },
})

const emit = defineEmits(['preview', 'cancel', 'delete', 'refresh', 'page-change'])

const showLoading = ref(false)
let loadingTimer = null

watch(() => props.loading, (val) => {
  clearTimeout(loadingTimer)
  if (val) {
    loadingTimer = setTimeout(() => { showLoading.value = true }, 200)
  } else {
    showLoading.value = false
  }
})

onUnmounted(() => clearTimeout(loadingTimer))

function isActive(s) { const st = (s ?? '').toLowerCase(); return st === 'running' || st === 'pending' }

function confirmCancel(id) { if (confirm(`¿Cancelar el escaneo #${id}?`)) emit('cancel', id) }
function confirmDelete(id) { if (confirm(`¿Eliminar el escaneo #${id}? Esta acción no se puede deshacer.`)) emit('delete', id) }

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('es-ES', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}
</script>

<style scoped>
.table-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; animation: seq-fade-up 0.3s ease-out; }
.table-toolbar { display: flex; align-items: center; justify-content: space-between; padding: 0.85rem 1.25rem; border-bottom: 1px solid var(--border); }
.toolbar-title { font-size: 0.85rem; font-weight: 600; color: var(--text-dim); }
.btn-refresh { display: flex; align-items: center; gap: 0.35rem; padding: 0.35rem 0.7rem; background: var(--surface-2); border: 1px solid var(--border); border-radius: 7px; color: var(--text-muted); font-size: 0.78rem; cursor: pointer; transition: all 0.2s; }
.btn-refresh:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.btn-refresh:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-refresh svg { width: 12px; height: 12px; }

table { width: 100%; border-collapse: collapse; }
th { padding: 0.65rem 1rem; text-align: left; font-size: 0.72rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; background: var(--surface-2); }
td { padding: 0.65rem 1rem; font-size: 0.85rem; border-top: 1px solid var(--border); color: var(--text); }
tr:hover td { background: rgba(255,255,255,0.015); }
.mono { font-family: var(--font-mono); font-size: 0.82rem; }
.muted { color: var(--text-muted); font-family: var(--font-body); font-size: 0.78rem; }
.date { font-size: 0.78rem; color: var(--text-dim); white-space: nowrap; }
.target { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sev-critical { color: var(--danger); font-weight: 600; }
.sev-high { color: var(--warn); font-weight: 600; }
.actions { display: flex; gap: 0.3rem; }
.act-btn { width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; color: var(--text-muted); cursor: pointer; transition: all 0.15s; }
.act-btn:hover { border-color: var(--accent); color: var(--accent); }
.act-btn svg { width: 14px; height: 14px; }
.act-btn.warn:hover { border-color: var(--warn); color: var(--warn); }
.act-btn.danger:hover { border-color: var(--danger); color: var(--danger); }

.empty-state { display: flex; flex-direction: column; align-items: center; gap: 0.5rem; padding: 3rem 1rem; color: var(--text-muted); font-size: 0.85rem; text-align: center; }
.empty-state svg { opacity: 0.25; }
.spin { animation: seq-spin 0.8s linear infinite; }
.table-footer { border-top: 1px solid var(--border); }

@media (max-width: 768px) {
  .target { max-width: 120px; }
}
</style>
