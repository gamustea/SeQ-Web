<template>
  <div class="queue-page">
    <Topbar title="Cola de Tareas" />

    <main class="main">
      <!-- Header + Status -->
      <div class="page-header">
        <div>
          <h1>Cola de Tareas</h1>
          <p class="subtitle">Monitoriza y gestiona las tareas asincronas en segundo plano</p>
        </div>
      </div>

      <!-- Status bar -->
      <div class="status-bar">
        <div class="stat-item">
          <span class="stat-label">Workers</span>
          <span class="stat-value">{{ store.status.aliveWorkers }} / {{ store.status.maxWorkers }}</span>
        </div>
        <div class="stat-item stat-item--running">
          <span class="stat-label">En ejecucion</span>
          <span class="stat-value">{{ store.status.runningCount }}</span>
        </div>
        <div class="stat-item stat-item--pending">
          <span class="stat-label">En espera</span>
          <span class="stat-value">{{ store.status.pendingCount }}</span>
        </div>
        <div class="stat-item stat-item--history">
          <span class="stat-label">Historial</span>
          <span class="stat-value">{{ store.status.historyCount }}</span>
        </div>
      </div>

      <!-- Tab bar -->
      <div class="tab-bar">
        <button
          class="tab-btn"
          :class="{ active: store.activeTab === 'running' }"
          @click="store.switchTab('running')"
        >
          En ejecucion
          <span class="tab-count">{{ store.status.runningCount }}</span>
        </button>
        <button
          class="tab-btn"
          :class="{ active: store.activeTab === 'pending' }"
          @click="store.switchTab('pending')"
        >
          En espera
          <span class="tab-count">{{ store.status.pendingCount }}</span>
        </button>
        <button
          class="tab-btn"
          :class="{ active: store.activeTab === 'history' }"
          @click="store.switchTab('history')"
        >
          Historial
          <span class="tab-count">{{ store.status.historyCount }}</span>
        </button>
      </div>

      <!-- Loading -->
      <div v-if="store.loading" class="loading-block">
        <div class="skeleton skeleton--row" v-for="i in 5" :key="i"></div>
      </div>

      <!-- Task list -->
      <div v-else-if="store.tasks.length > 0" class="task-list">
        <div v-for="task in store.tasks" :key="task.id" class="task-row" :class="'task-row--' + task.status">
          <div class="task-icon" :class="'task-icon--' + task.status">
            <svg v-if="task.status === 'running'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polygon points="5 3 19 12 5 21 5 3"/>
            </svg>
            <svg v-else-if="task.status === 'pending'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
            </svg>
            <svg v-else-if="task.status === 'completed'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
            <svg v-else-if="task.status === 'cancelled'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
            </svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>

          <div class="task-info">
            <div class="task-name">{{ task.name }}</div>
            <span class="task-category">{{ categoryLabel(task.category) }}</span>
            <span class="task-status-badge" :class="'status--' + task.status">{{ statusLabel(task.status) }}</span>
          </div>

          <div class="task-times">
            <span class="task-time">Creado: {{ formatDate(task.createdAt) }}</span>
            <span v-if="task.startedAt" class="task-time">Inicio: {{ formatDate(task.startedAt) }}</span>
            <span v-if="task.finishedAt" class="task-time">Fin: {{ formatDate(task.finishedAt) }}</span>
            <span v-if="task.error" class="task-error">{{ task.error }}</span>
          </div>

          <!-- Progress bar -->
          <div v-if="task.status === 'running'" class="task-progress">
            <div class="progress-track">
              <div class="progress-fill" :style="{ width: task.progress + '%' }"></div>
            </div>
            <span class="progress-text">{{ task.progress }}%</span>
          </div>

          <!-- Cancel button -->
          <button
            v-if="task.status === 'pending' || task.status === 'running'"
            class="btn-cancel"
            @click="handleCancel(task.id)"
          >
            Cancelar
          </button>
        </div>
      </div>

      <!-- Empty -->
      <div v-else class="empty-state">
        No hay tareas en esta categoria.
      </div>

      <!-- Pagination -->
      <AppPagination
        :current="store.currentPage"
        :total="store.totalCount"
        :per-page="store.perPage"
        @go="store.goToPage"
      />
    </main>

    <StarBackground />
    <AppToast />
  </div>
</template>

<script setup>
/**
 * QueueView — Panel de administracion de la cola de tareas (SeQueue).
 *
 * Muestra las tareas en ejecucion, en espera e historial,
 * permite cancelar tareas y ajustar el numero maximo de workers.
 * Solo accesible para administradores.
 */
import { onMounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import AppPagination from '@/components/shared/AppPagination.vue'
import { useQueueStore } from '@/stores/queueStore'
import { useUtils } from '@/composables/useUtils'

const store = useQueueStore()
const { formatDate } = useUtils()

onMounted(() => {
  store.loadStatus()
  store.loadTasks()
})

function categoryLabel(category) {
  const map = {
    'sentinel.scan': 'Escaneo',
    'sentinel.report': 'Informe PDF',
    'aegis.generate': 'IA Aegis',
  }
  return map[category] || category
}

function statusLabel(status) {
  const map = {
    pending: 'Pendiente',
    running: 'En ejecucion',
    completed: 'Completado',
    failed: 'Fallido',
    cancelled: 'Cancelado',
  }
  return map[status] || status
}

async function handleCancel(taskId) {
  await store.cancelTask(taskId)
}
</script>

<style scoped>
.queue-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); }
.main { max-width: 1000px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }

/* Header */
.page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem; }
.page-header h1 { font-size: 1.6rem; font-weight: 800; color: var(--text); margin: 0; }
.subtitle { font-size: 0.88rem; color: var(--text-dim); margin: 0.25rem 0 0; }

/* Status bar */
.status-bar { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; padding: 1rem 1.25rem; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 1.5rem; }
.stat-item { display: flex; flex-direction: column; gap: 0.15rem; min-width: 100px; }
.stat-label { font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.03em; font-weight: 600; }
.stat-value { font-size: 1.2rem; font-weight: 700; color: var(--text); font-family: var(--font-mono); }
.stat-item--running .stat-value { color: var(--info); }
.stat-item--pending .stat-value { color: var(--warn); }
.stat-item--history .stat-value { color: var(--text-dim); }

/* Tab bar */
.tab-bar { display: flex; gap: 0.35rem; margin-bottom: 1.25rem; border-bottom: 1px solid var(--border); padding-bottom: 0; }
.tab-btn {
  padding: 0.6rem 1.1rem; border: none; background: none; color: var(--text-dim);
  font-size: 0.88rem; font-weight: 600; cursor: pointer; border-radius: 8px 8px 0 0;
  border-bottom: 2px solid transparent; display: flex; align-items: center; gap: 0.45rem;
  transition: all 0.2s ease;
}
.tab-btn:hover { color: var(--text); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab-count { font-size: 0.7rem; padding: 0.1rem 0.45rem; border-radius: 10px; background: var(--surface-2); font-family: var(--font-mono); }

/* Task list */
.task-list { display: flex; flex-direction: column; gap: 0.5rem; }

.task-row {
  display: flex; align-items: center; gap: 1rem; padding: 1rem 1.25rem;
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  transition: border-color 0.2s; flex-wrap: wrap;
}
.task-row:hover { border-color: var(--border-med); }
.task-row--running { border-left: 3px solid var(--info); }
.task-row--pending { border-left: 3px solid var(--warn); }
.task-row--completed { border-left: 3px solid var(--success); }
.task-row--failed { border-left: 3px solid var(--danger); }
.task-row--cancelled { border-left: 3px solid var(--text-muted); opacity: 0.6; }

.task-icon {
  width: 36px; height: 36px; border-radius: 8px; display: flex; align-items: center;
  justify-content: center; flex-shrink: 0; border: 1px solid var(--border);
}
.task-icon svg { width: 18px; height: 18px; }
.task-icon--running { background: var(--info); border-color: var(--info); color: #fff; }
.task-icon--pending { background: var(--warn-dim); border-color: var(--warn); color: var(--warn); }
.task-icon--completed { background: var(--success-dim); border-color: var(--success); color: var(--success); }
.task-icon--failed { background: var(--danger-dim); border-color: var(--danger); color: var(--danger); }
.task-icon--cancelled { background: var(--surface-2); border-color: var(--border); color: var(--text-muted); }

.task-info { display: flex; flex-direction: column; gap: 0.15rem; flex: 1; min-width: 180px; }
.task-name { font-weight: 700; color: var(--text); font-size: 0.92rem; }
.task-category { font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono); }

.task-status-badge {
  display: inline-block; padding: 0.15rem 0.55rem; border-radius: 20px;
  font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.04em; width: fit-content;
}
.status--pending { background: var(--warn-dim); color: var(--warn); border: 1px solid rgba(251, 191, 36, 0.2); }
.status--running { background: var(--info-dim, rgba(59, 130, 246, 0.12)); color: var(--info); border: 1px solid rgba(59, 130, 246, 0.2); }
.status--completed { background: var(--success-dim); color: var(--success); border: 1px solid rgba(52, 211, 153, 0.2); }
.status--failed { background: var(--danger-dim); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.2); }
.status--cancelled { background: var(--surface-2); color: var(--text-muted); }

.task-times { display: flex; flex-direction: column; gap: 0.1rem; flex: 1.2; min-width: 160px; }
.task-time { font-size: 0.72rem; color: var(--text-dim); font-family: var(--font-mono); }
.task-error { font-size: 0.7rem; color: var(--danger); margin-top: 0.2rem; word-break: break-word; max-width: 280px; }

.task-progress { display: flex; align-items: center; gap: 0.5rem; width: 120px; flex-shrink: 0; }
.progress-track { flex: 1; height: 4px; background: var(--surface-2); border-radius: 2px; overflow: hidden; }
.progress-fill { height: 100%; background: var(--info); border-radius: 2px; transition: width 0.6s ease; }
.progress-text { font-size: 0.68rem; color: var(--text-muted); font-family: var(--font-mono); min-width: 32px; text-align: right; }

.btn-cancel {
  padding: 0.4rem 0.8rem; border-radius: 7px; border: 1px solid var(--danger);
  background: var(--danger-dim); color: var(--danger); font-size: 0.75rem;
  font-weight: 600; cursor: pointer; transition: all 0.2s ease; flex-shrink: 0;
}
.btn-cancel:hover { background: var(--danger); color: #fff; }

/* Loading */
.loading-block { display: flex; flex-direction: column; gap: 0.5rem; padding: 2rem 0; }
.skeleton { background: var(--surface); border-radius: 10px; animation: pulse 1.4s ease-in-out infinite; }
.skeleton--row { width: 100%; height: 64px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

/* Empty */
.empty-state { text-align: center; padding: 4rem 0; color: var(--text-muted); font-size: 0.95rem; }

/* Pagination margin */
.pagination { margin-top: 1.5rem; }

@media (max-width: 768px) {
  .status-bar { gap: 0.5rem; }
  .stat-item { min-width: 70px; }
  .task-row { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
  .task-progress { width: 100%; }
  .btn-cancel { align-self: flex-end; }
}
</style>
