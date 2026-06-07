<template>
  <div class="history-strip">
    <div class="strip-scroll">
      <!-- New analysis button -->
      <button
        type="button"
        class="strip-item strip-item--new"
        :class="{ active: activeId === null }"
        @click="$emit('select', null)"
        title="Nuevo análisis"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="new-icon">
          <line x1="12" y1="5" x2="12" y2="19"/>
          <line x1="5" y1="12" x2="19" y2="12"/>
        </svg>
        <span>Nuevo</span>
      </button>

      <!-- Analysis items -->
      <div
        v-for="item in items"
        :key="item.analysisId"
        class="strip-item-wrap"
        @mouseenter="hoverId = item.analysisId"
        @mouseleave="hoverId = null"
      >
        <button
          type="button"
          class="strip-item"
          :class="{
            active: activeId === item.analysisId,
            'strip-item--finished': item.status === 'finished',
            'strip-item--running': item.status === 'running' || item.status === 'pending',
            'strip-item--failed': item.status === 'failed',
            'strip-item--cancelled': item.status === 'cancelled',
          }"
          @click="$emit('select', item.analysisId)"
        >
          <span class="strip-dot" :class="`dot--${item.status || 'pending'}`"></span>
          <span v-if="item.title" class="strip-title">{{ item.title }}</span>
          <span v-else class="strip-id">#{{ item.analysisId }}</span>
          <span v-if="item.verdict && item.status === 'finished'" class="strip-verdict" :class="`verdict--${verdictClass(item.verdict)}`">
            {{ item.totalScore }}
          </span>
          <span v-else-if="item.status === 'running' || item.status === 'pending'" class="strip-status">{{ item.status }}</span>
        </button>

        <!-- Delete button (visible on hover) -->
        <button
          v-if="!confirmDeleteId || confirmDeleteId !== item.analysisId"
          type="button"
          class="strip-del"
          :class="{ 'strip-del--visible': hoverId === item.analysisId }"
          title="Eliminar"
          @click.stop="confirmDeleteId = item.analysisId"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
        </button>

        <!-- Inline confirmation -->
        <div v-else-if="confirmDeleteId === item.analysisId" class="strip-confirm">
          <span class="confirm-text">¿Eliminar #{{ item.analysisId }}?</span>
          <button type="button" class="confirm-yes" title="Sí" @click.stop="handleDelete(item.analysisId)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
          </button>
          <button type="button" class="confirm-no" title="No" @click.stop="confirmDeleteId = null">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
      </div>

      <div class="strip-fade"></div>
    </div>

    <div class="strip-tools">
      <button type="button" class="tool-btn" title="Ordenar" @click="sortOpen = !sortOpen">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="6" x2="20" y2="6"/><line x1="8" y1="12" x2="16" y2="12"/><line x1="12" y1="18" x2="12" y2="18"/></svg>
      </button>
      <div v-if="sortOpen" class="sort-menu">
        <button :class="{ active: sort === 'date-desc' }" @click="changeSort('date-desc')">Más recientes</button>
        <button :class="{ active: sort === 'date-asc' }" @click="changeSort('date-asc')">Más antiguos</button>
        <button :class="{ active: sort === 'score-desc' }" @click="changeSort('score-desc')">Mayor score</button>
        <button :class="{ active: sort === 'score-asc' }" @click="changeSort('score-asc')">Menor score</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  items: { type: Array, default: () => [] },
  activeId: { type: [Number, null], default: null },
  sort: { type: String, default: 'date-desc' },
})

const emit = defineEmits(['select', 'sort', 'delete'])

const sortOpen = ref(false)
const hoverId = ref(null)
const confirmDeleteId = ref(null)

function changeSort(val) {
  sortOpen.value = false
  emit('sort', val)
}

function handleDelete(id) {
  confirmDeleteId.value = null
  emit('delete', id)
}

function verdictClass(v) {
  if (!v) return 'unknown'
  const l = v.toLowerCase()
  if (l === 'legitimate') return 'legit'
  if (l === 'suspicious') return 'susp'
  if (l === 'phishing') return 'phish'
  return 'unknown'
}
</script>

<style scoped>
.history-strip {
  display: flex;
  align-items: center;
  height: 54px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  position: relative;
}

.strip-scroll {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 0 0.65rem;
  overflow-x: auto;
  overflow-y: hidden;
  scrollbar-width: none;
  -ms-overflow-style: none;
}

.strip-scroll::-webkit-scrollbar {
  display: none;
}

.strip-item {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.45rem 0.7rem;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-dim);
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
  flex-shrink: 0;
  height: 36px;
}

.strip-item:hover {
  border-color: var(--border-med);
  color: var(--text);
  background: var(--surface-2);
}

.strip-item.active {
  border-color: var(--accent);
  background: var(--accent-dim);
  color: var(--accent-bright);
}

.strip-item--new {
  border-style: dashed;
  gap: 0.2rem;
}

.strip-item-wrap {
  display: flex;
  align-items: center;
  gap: 2px;
  flex-shrink: 0;
  position: relative;
}

.strip-del {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: 5px;
  border: 1px solid transparent;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.15s;
  opacity: 0;
  flex-shrink: 0;
}

.strip-del--visible {
  opacity: 1;
  border-color: var(--border);
}

.strip-del:hover {
  border-color: var(--danger);
  color: var(--danger);
  background: var(--danger-dim);
}

.strip-del svg {
  width: 13px;
  height: 13px;
}

.strip-confirm {
  display: flex;
  align-items: center;
  gap: 3px;
  padding: 0 0.3rem;
  height: 30px;
  border-radius: 5px;
  background: var(--surface);
  border: 1px solid var(--danger);
  flex-shrink: 0;
}

.confirm-text {
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--danger);
  white-space: nowrap;
}

.confirm-yes,
.confirm-no {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  border-radius: 4px;
  border: none;
  cursor: pointer;
  transition: all 0.12s;
}

.confirm-yes {
  background: var(--danger-dim);
  color: var(--danger);
}

.confirm-yes:hover {
  background: var(--danger);
  color: #0b0c10;
}

.confirm-no {
  background: var(--surface-2);
  color: var(--text-muted);
}

.confirm-no:hover {
  background: var(--surface-3);
  color: var(--text-dim);
}

.confirm-yes svg,
.confirm-no svg {
  width: 12px;
  height: 12px;
}

.new-icon {
  width: 16px;
  height: 16px;
}

.strip-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.dot--finished { background: var(--success); }
.dot--running,
.dot--pending { background: var(--info); animation: seq-pulse 1.5s infinite; }
.dot--failed { background: var(--danger); }
.dot--cancelled { background: var(--text-muted); }

.strip-id {
  font-family: var(--font-mono);
  font-size: 0.82rem;
}

.strip-title {
  font-family: var(--font-body);
  font-size: 0.82rem;
  font-weight: 500;
  max-width: 160px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.strip-verdict {
  font-family: var(--font-mono);
  font-size: 0.8rem;
  font-weight: 700;
  margin-left: 0.15rem;
}

.strip-verdict.verdict--legit { color: var(--success); }
.strip-verdict.verdict--susp { color: var(--warn); }
.strip-verdict.verdict--phish { color: var(--danger); }

.strip-status {
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-muted);
  font-weight: 600;
}

.strip-fade {
  position: sticky;
  right: 0;
  width: 28px;
  height: 100%;
  background: linear-gradient(90deg, transparent, var(--surface));
  flex-shrink: 0;
  pointer-events: none;
}

.strip-tools {
  position: relative;
  flex-shrink: 0;
  padding-right: 0.65rem;
}

.tool-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.15s;
}

.tool-btn:hover {
  border-color: var(--accent);
  color: var(--accent);
  background: var(--accent-dim);
}

.tool-btn svg {
  width: 16px;
  height: 16px;
}

.sort-menu {
  position: absolute;
  right: 0.65rem;
  top: 100%;
  margin-top: 5px;
  z-index: 30;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 8px;
  overflow: hidden;
  min-width: 160px;
  box-shadow: 0 8px 20px rgba(0,0,0,0.4);
}

.sort-menu button {
  display: block;
  width: 100%;
  text-align: left;
  padding: 0.5rem 0.8rem;
  font-size: 0.82rem;
  background: none;
  border: none;
  color: var(--text-dim);
  cursor: pointer;
  transition: background 0.1s;
  font-family: var(--font-body);
}

.sort-menu button:hover,
.sort-menu button.active {
  background: var(--accent-dim);
  color: var(--accent-bright);
}
</style>
