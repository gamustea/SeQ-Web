<template>
  <nav class="topbar">
    <div class="topbar-left">
      <router-link to="/hub" class="back-link">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M19 12H5M12 5l-7 7 7 7"/>
        </svg>
        Hub
      </router-link>
      <span class="topbar-sep">|</span>
      <span class="topbar-title">{{ title }}</span>
      <span v-if="badge" class="topbar-badge">{{ badge }}</span>
    </div>
    <div class="topbar-right">
      <div class="session-pill">
        <div class="session-dot"></div>
        <span>{{ auth.username() }}</span>
      </div>
      <button class="btn-logout" @click="auth.logout">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
          <polyline points="16 17 21 12 16 7"/>
          <line x1="21" y1="12" x2="9" y2="12"/>
        </svg>
        Cerrar sesión
      </button>
    </div>
  </nav>
</template>

<script setup>
/**
 * Topbar — Barra superior reutilizable para las vistas de los módulos.
 *
 * Muestra el enlace de vuelta al Hub, el título del módulo actual,
 * el nombre del usuario autenticado y el botón de cierre de sesión.
 *
 * @vue-prop {string} title - Título del módulo (Sentinel, Aegis, etc.)
 * @vue-prop {string} [badge=''] - Etiqueta contextual opcional
 *
 * @example
 * <Topbar title="Sentinel" badge="Escaneos de Vulnerabilidades" />
 */
import { useAuthStore } from '@/stores/authStore'

defineProps({
  /** Título principal de la página */
  title: { type: String, required: true },
  /** Badge opcional (subtítulo o estado) */
  badge: { type: String, default: '' },
})

const auth = useAuthStore()
</script>

<style scoped>
.topbar { position: fixed; top: 0; left: 0; right: 0; z-index: 50; display: flex; align-items: center; justify-content: space-between; padding: .65rem 1.25rem; height: var(--topbar-h); background: rgba(8,12,20,0.88); backdrop-filter: blur(16px); border-bottom: 1px solid var(--border); }
.topbar-left { display: flex; align-items: center; gap: .6rem; }
.back-link { display: flex; align-items: center; gap: .3rem; color: var(--text-dim); text-decoration: none; font-size: .85rem; }
.back-link:hover { color: var(--text); }
.back-link svg { width: 16px; height: 16px; }
.topbar-sep { color: var(--text-muted); font-size: .8rem; }
.topbar-title { font-weight: 600; color: var(--text); font-size: .95rem; }
.topbar-badge { font-size: .72rem; color: var(--text-muted); background: var(--surface-2); padding: .15rem .5rem; border-radius: 6px; }
.topbar-right { display: flex; align-items: center; gap: 1rem; }
.session-pill { display: flex; align-items: center; gap: .35rem; font-size: .8rem; color: var(--text-dim); }
.session-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--success); }
.btn-logout { display: flex; align-items: center; gap: .35rem; background: none; border: none; color: var(--text-muted); font-size: .8rem; cursor: pointer; padding: .3rem .5rem; border-radius: 6px; transition: background .2s; }
.btn-logout:hover { background: var(--danger-dim); color: var(--danger); }
.btn-logout svg { width: 14px; height: 14px; }
</style>
