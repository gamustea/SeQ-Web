<template>
  <div class="history-panel">
    <div class="history-header">
      <h2>Historial</h2>
      <span class="history-count">{{ documents.length }} doc(s)</span>
    </div>

    <div class="history-controls">
      <select class="input select sort" v-model="sortModeLocal" @change="$emit('sort', sortModeLocal)">
        <option value="date-desc">Más recientes</option>
        <option value="date-asc">Más antiguos</option>
        <option value="name-asc">Nombre A–Z</option>
        <option value="status">Estado</option>
      </select>
      <button type="button" class="btn-icon" :class="{ spinning }" @click="handleRefresh" title="Refrescar">&#8635;</button>
    </div>

    <div class="history-list">
      <div v-if="documents.length === 0" class="history-empty">Sin documentos aún</div>

      <div
        v-for="doc in documents"
        :key="doc.id"
        class="history-item"
        :class="{ active: doc.id === currentDocId }"
      >
        <div class="item-info" @click="$emit('view', doc.id)">
          <div class="item-title">{{ doc.title || `Documento #${doc.id}` }}</div>
          <div class="item-meta">
            <span class="item-status" :class="`status--${doc.status || 'pending'}`">{{ statusLabel(doc.status) }}</span>
            <span class="item-topic">Tema #{{ doc.topicId }}</span>
            <span class="item-date">{{ formatDate(doc.generatedAt) }}</span>
          </div>
        </div>
        <div class="item-actions">
          <button type="button" class="action-btn" title="Ver" @click="$emit('view', doc.id)">&#128065;</button>
          <div class="export-mini">
            <button type="button" class="action-btn" title="Exportar" @click="exportOpen = exportOpen === doc.id ? null : doc.id">&#128196;</button>
            <div v-if="exportOpen === doc.id" class="export-mini-menu">
              <button @click="emitExport(doc.id, 'md')">MD</button>
              <button @click="emitExport(doc.id, 'html')">HTML</button>
              <button @click="emitExport(doc.id, 'json')">JSON</button>
            </div>
          </div>
          <button type="button" class="action-btn action-btn--danger" title="Eliminar" @click="confirmDelete(doc.id)">&#10005;</button>
        </div>
      </div>
    </div>
  </div>

  <Teleport to="body">
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal modal--confirm">
        <p>¿Eliminar el documento <strong>#{{ deleteTarget }}</strong>?</p>
        <div class="modal-actions">
          <button type="button" class="btn btn--secondary" @click="deleteTarget = null">Cancelar</button>
          <button type="button" class="btn btn--danger" @click="doDelete">Eliminar</button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { ref } from 'vue'
import { useUtils } from '@/composables/useUtils'

const { formatDate } = useUtils()

const props = defineProps({
  documents: { type: Array, default: () => [] },
  currentDocId: { type: [Number, null], default: null },
  sortMode: { type: String, default: 'date-desc' },
})

const emit = defineEmits(['view', 'delete', 'export', 'preview', 'sort', 'refresh'])

const sortModeLocal = ref(props.sortMode)
const spinning = ref(false)
const exportOpen = ref(null)
const deleteTarget = ref(null)

const statusLabels = { done: 'Listo', pending: 'Generando', error: 'Error' }
function statusLabel(s) { return statusLabels[s] || s || '—' }

function emitExport(docId, fmt) { exportOpen.value = null; emit('export', docId, fmt) }

async function handleRefresh() {
  spinning.value = true
  emit('refresh')
  setTimeout(() => { spinning.value = false }, 800)
}

function confirmDelete(id) { deleteTarget.value = id }
function doDelete() { emit('delete', deleteTarget.value); deleteTarget.value = null }
</script>

<style scoped>
.history-panel { display: flex; flex-direction: column; height: 100%; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }

.history-header {
  display: flex; align-items: baseline; justify-content: space-between;
  padding: 1rem 1.25rem 0.5rem;
}
.history-header h2 { font-size: 1.1rem; font-weight: 700; color: var(--text); margin: 0; }
.history-count { font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono); }

.history-controls { display: flex; align-items: center; gap: 0.5rem; padding: 0 1.25rem 0.75rem; border-bottom: 1px solid var(--border); }
.sort { flex: 1; padding: 0.35rem 0.5rem; font-size: 0.78rem; }
.input { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); outline: none; }
.input:focus { border-color: var(--accent); }
.select { cursor: pointer; }

.btn-icon {
  width: 30px; height: 30px; border-radius: 6px; border: 1px solid var(--border);
  background: var(--bg); color: var(--text-dim); font-size: 1.1rem; cursor: pointer;
  display: flex; align-items: center; justify-content: center; transition: background 0.2s;
}
.btn-icon:hover { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.btn-icon.spinning { animation: spin 0.7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

.history-list { flex: 1; overflow-y: auto; padding: 0.5rem; }

.history-empty { text-align: center; padding: 2.5rem 1rem; color: var(--text-muted); font-size: 0.82rem; }

.history-item {
  display: flex; align-items: center; gap: 0.5rem; padding: 0.65rem 0.75rem;
  border-radius: 8px; cursor: default; transition: background 0.15s; margin-bottom: 2px;
}
.history-item:hover { background: var(--bg); }
.history-item.active { background: var(--bg); border: 1px solid var(--accent); padding: calc(0.65rem - 1px) calc(0.75rem - 1px); }

.item-info { flex: 1; min-width: 0; cursor: pointer; }
.item-title { font-size: 0.85rem; font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.item-meta { display: flex; align-items: center; gap: 0.4rem; margin-top: 0.15rem; font-size: 0.7rem; color: var(--text-muted); }
.item-status {
  padding: 0.1rem 0.35rem; border-radius: 3px; font-weight: 600; font-size: 0.65rem; text-transform: uppercase;
}
.status--done    { background: rgba(52,211,153,0.15); color: var(--success); }
.status--pending { background: rgba(251,191,36,0.15); color: var(--warn); }
.status--error   { background: rgba(239,68,68,0.15); color: var(--danger); }

.item-actions { display: flex; gap: 0.2rem; flex-shrink: 0; align-items: center; }

.action-btn {
  width: 26px; height: 26px; border-radius: 5px; border: 1px solid transparent;
  background: none; color: var(--text-muted); font-size: 0.75rem; cursor: pointer;
  display: flex; align-items: center; justify-content: center; transition: all 0.15s;
}
.action-btn:hover { background: var(--bg); border-color: var(--border); color: var(--text); }
.action-btn--danger:hover { color: var(--danger); border-color: rgba(239,68,68,0.3); }

.export-mini { position: relative; }
.export-mini-menu {
  position: absolute; right: 0; top: 100%; margin-top: 2px; z-index: 25;
  background: var(--surface); border: 1px solid var(--border); border-radius: 5px; overflow: hidden; min-width: 60px;
}
.export-mini-menu button {
  display: block; width: 100%; text-align: left; padding: 0.25rem 0.5rem;
  font-size: 0.65rem; font-weight: 600; background: none; border: none; color: var(--text-dim); cursor: pointer;
}
.export-mini-menu button:hover { background: var(--accent); color: var(--bg); }
</style>

<style>
/* Unscoped modal styles (Teleported to body) */
.modal-overlay { position: fixed; inset: 0; z-index: 200; background: rgba(0,0,0,.65); display: flex; align-items: center; justify-content: center; padding: 1.5rem; }
.modal--confirm { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; max-width: 360px; width: 100%; }
.modal--confirm p { font-size: 0.9rem; color: var(--text); margin: 0 0 1rem; }
.modal-actions { display: flex; gap: 0.5rem; justify-content: flex-end; }
.btn { padding: 0.5rem 1.25rem; border-radius: 7px; font-size: 0.85rem; font-weight: 600; border: 1px solid transparent; cursor: pointer; transition: background 0.2s; }
.btn--secondary { background: transparent; color: var(--text-dim); border-color: var(--border); }
.btn--secondary:hover { background: var(--border); color: var(--text); }
.btn--danger { background: var(--danger); color: #fff; }
.btn--danger:hover { filter: brightness(1.15); }
</style>
