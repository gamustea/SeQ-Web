<template>
  <div class="hub-page">
    <!-- Sidebar toggle -->
    <button
      class="sidebar-toggle"
      :class="{ active: sidebarOpen }"
      @click="sidebarOpen = !sidebarOpen"
      aria-label="Menú de perfil"
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="3" y1="12" x2="21" y2="12"/>
        <line x1="3" y1="6" x2="21" y2="6"/>
        <line x1="3" y1="18" x2="21" y2="18"/>
      </svg>
    </button>

    <!-- Profile sidebar -->
    <Transition name="sidebar">
      <aside v-show="sidebarOpen" class="profile-sidebar" ref="sidebarRef">
        <div class="profile-header">
          <div class="profile-avatar-wrap">
            <img :src="'/resources/images/default-avatar.svg'" alt="Perfil" class="profile-avatar" />
            <div class="avatar-glow"></div>
          </div>
          <!-- Skeleton while loading name, real name when ready -->
          <div class="profile-name-wrap">
            <h3 v-if="profileLoaded" class="profile-name">{{ profileName }}</h3>
            <div v-else class="skeleton-name"></div>
          </div>
          <p v-if="profileLoaded" class="profile-role">{{ roleLabel }}</p>
        </div>
        <nav class="profile-menu">
          <router-link to="/profile" class="menu-item" @click="sidebarOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
              <circle cx="12" cy="7" r="4"/>
            </svg>
            Perfil
          </router-link>
          <router-link v-if="auth.isAdmin" to="/users" class="menu-item" @click="sidebarOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
              <circle cx="9" cy="7" r="4"/>
              <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
              <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
            </svg>
            Usuarios
          </router-link>
          <router-link v-if="auth.isAdmin" to="/config" class="menu-item" @click="sidebarOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
            Configuración
          </router-link>
          <router-link v-if="auth.isAdmin" to="/queue" class="menu-item" @click="sidebarOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
              <line x1="8" y1="9" x2="16" y2="9"/>
              <line x1="8" y1="13" x2="14" y2="13"/>
            </svg>
            Cola de Tareas
          </router-link>
          <button class="menu-item menu-item--danger" @click="logout">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
              <polyline points="16 17 21 12 16 7"/>
              <line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
            Cerrar sesión
          </button>
        </nav>
      </aside>
    </Transition>

    <!-- Backdrop for sidebar on mobile -->
    <Transition name="fade">
      <div v-if="sidebarOpen" class="sidebar-backdrop" @click="sidebarOpen = false"></div>
    </Transition>

    <!-- Header -->
    <header class="hub-header">
      <div class="hub-logo">
        <span class="logo-bracket">[</span>
        <span class="logo-text">SeQ</span>
        <span class="logo-bracket">]</span>
      </div>
      <p class="hub-subtitle">Security Operations Platform</p>
      <div class="hub-version">v2.0 — Vue SPA</div>
    </header>

    <!-- Module cards grid -->
    <main class="hub-grid">
      <!-- Sentinel -->
      <router-link
        to="/sentinel"
        class="module-card module-sentinel"
        :style="{ animationDelay: '0.1s' }"
      >
        <div class="card-glow"></div>
        <div class="card-shine"></div>
        <div class="card-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="11" cy="11" r="8"/>
            <path d="M21 21l-4.35-4.35"/>
            <path d="M11 8v3l2 2"/>
          </svg>
        </div>
        <div class="card-content">
          <h2 class="card-title">Sentinel</h2>
          <p class="card-desc">Escaneo de red, análisis de vulnerabilidades y generación de informes con IA.</p>
          <div class="card-meta">
            <span class="card-badge card-badge--active">
              <span class="badge-dot"></span>
              Operativo
            </span>
            <span class="card-count">3 escáneres</span>
          </div>
        </div>
        <div class="card-arrow">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M5 12h14M12 5l7 7-7 7"/>
          </svg>
        </div>
      </router-link>

      <!-- Aegis -->
      <router-link
        to="/aegis"
        class="module-card module-aegis"
        :style="{ animationDelay: '0.25s' }"
      >
        <div class="card-glow"></div>
        <div class="card-shine"></div>
        <div class="card-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"/>
            <path d="M9 12l2 2 4-4"/>
          </svg>
        </div>
        <div class="card-content">
          <h2 class="card-title">Aegis</h2>
          <p class="card-desc">Newsletter de inteligencia de seguridad generada por IA para concienciación.</p>
          <div class="card-meta">
            <span class="card-badge card-badge--active">
              <span class="badge-dot"></span>
              Operativo
            </span>
            <span class="card-count">Exporta MD / JSON</span>
          </div>
        </div>
        <div class="card-arrow">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M5 12h14M12 5l7 7-7 7"/>
          </svg>
        </div>
      </router-link>

      <!-- Acheron (disabled) -->
      <div
        class="module-card module-acheron module-disabled"
        :style="{ animationDelay: '0.4s' }"
      >
        <div class="card-glow"></div>
        <div class="card-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            <circle cx="12" cy="16" r="1"/>
          </svg>
        </div>
        <div class="card-content">
          <h2 class="card-title">Acheron</h2>
          <p class="card-desc">Bóveda cifrada de credenciales y tarjetas para tu organización.</p>
          <div class="card-meta">
            <span class="card-badge card-badge--later">Pendiente</span>
          </div>
        </div>
        <div class="wip-overlay">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="32" height="32">
            <circle cx="12" cy="12" r="10"/>
            <polyline points="12 6 12 12 16 14"/>
          </svg>
          <span>Disponible más adelante</span>
        </div>
      </div>
    </main>

    <!-- Footer -->
    <footer class="hub-footer">
      <span>SeQ Platform &mdash; Security Operations Suite</span>
    </footer>
  </div>
</template>

<script setup>
/**
 * HubView — Dashboard principal de la plataforma.
 *
 * Sustituye a hub.html + hub.js. Muestra el logo de SeQ,
 * los módulos disponibles y un sidebar de perfil.
 */
import { ref, onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/authStore'
import { useApi } from '@/composables/useApi'

const auth = useAuthStore()
const { apiFetch } = useApi()

const sidebarOpen = ref(false)
const profileName = ref('Usuario')
const profileLoaded = ref(false)
const sidebarRef = ref(null)

/** Determina el label del rol para mostrar */
const roleLabel = ref('Usuario')

let clickOutsideHandler = null

onMounted(() => {
  loadProfileName()

  clickOutsideHandler = (e) => {
    const sb = sidebarRef.value
    const tb = document.querySelector('.sidebar-toggle')
    if (sb && tb && !sb.contains(e.target) && !tb.contains(e.target)) {
      sidebarOpen.value = false
    }
  }
  document.addEventListener('click', clickOutsideHandler)
})

onUnmounted(() => {
  if (clickOutsideHandler) {
    document.removeEventListener('click', clickOutsideHandler)
  }
})

async function loadProfileName() {
  try {
    const res = await apiFetch('/users/me')
    if (res?.ok) {
      const data = await res.json()
      profileName.value = `${data.first_name} ${data.last_name}`
      const r = data.role || auth.role
      if (r === 'role_root') roleLabel.value = 'Root'
      else if (r === 'role_admin') roleLabel.value = 'Administrador'
      else roleLabel.value = 'Usuario'
    }
  } catch {
    profileName.value = auth.username() || 'Usuario'
  } finally {
    profileLoaded.value = true
  }
}

function logout() {
  sidebarOpen.value = false
  auth.logout()
}
</script>

<style scoped>
/* ═══════════════════════════════════════════════════════════
   HUB PAGE — Layout & Background
   ═══════════════════════════════════════════════════════════ */
.hub-page {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  position: relative;
  overflow-x: hidden;
}

/* ═══════════════════════════════════════════════════════════
   SIDEBAR TOGGLE
   ═══════════════════════════════════════════════════════════ */
.sidebar-toggle {
  position: fixed;
  top: 1.25rem;
  left: 1.25rem;
  z-index: 101;
  width: 44px;
  height: 44px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 0.6rem;
  color: var(--text-muted);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.25s ease;
  backdrop-filter: blur(8px);
}
.sidebar-toggle svg {
  width: 22px;
  height: 22px;
  transition: transform 0.25s ease;
}
.sidebar-toggle:hover {
  border-color: var(--accent);
  color: var(--accent);
  box-shadow: 0 0 16px var(--accent-dim);
}
.sidebar-toggle.active {
  border-color: var(--accent);
  color: var(--accent);
}
.sidebar-toggle.active svg {
  transform: rotate(90deg);
}

/* ═══════════════════════════════════════════════════════════
   SIDEBAR — Profile panel
   ═══════════════════════════════════════════════════════════ */
.sidebar-enter-active,
.sidebar-leave-active {
  transition: transform 0.35s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.3s ease;
}
.sidebar-enter-from,
.sidebar-leave-to {
  transform: translateX(-100%);
  opacity: 0;
}

.profile-sidebar {
  position: fixed;
  top: 0;
  left: 0;
  width: 280px;
  height: 100vh;
  background: var(--surface);
  border-right: 1px solid var(--border);
  z-index: 100;
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  overflow-y: auto;
}

.profile-header {
  text-align: center;
  padding: 2.5rem 0 1.5rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 1.25rem;
}

.profile-avatar-wrap {
  position: relative;
  display: inline-block;
  margin-bottom: 1rem;
}
.profile-avatar {
  width: 72px;
  height: 72px;
  border-radius: 50%;
  background: var(--surface-2);
  border: 2px solid var(--border);
  position: relative;
  z-index: 1;
  transition: border-color 0.3s ease;
}
.profile-avatar-wrap:hover .profile-avatar {
  border-color: var(--accent);
}
.avatar-glow {
  position: absolute;
  inset: -6px;
  border-radius: 50%;
  background: radial-gradient(circle, var(--accent-dim) 0%, transparent 70%);
  opacity: 0;
  transition: opacity 0.3s ease;
}
.profile-avatar-wrap:hover .avatar-glow {
  opacity: 1;
}

.profile-name-wrap {
  min-height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.profile-name {
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--text);
  letter-spacing: -0.01em;
}
.profile-role {
  font-size: 0.8rem;
  color: var(--text-muted);
  margin-top: 0.25rem;
  font-weight: 500;
}

/* Skeleton shimmer for loading name */
.skeleton-name {
  width: 140px;
  height: 20px;
  border-radius: 6px;
  background: linear-gradient(
    90deg,
    var(--surface-2) 25%,
    var(--surface-3) 50%,
    var(--surface-2) 75%
  );
  background-size: 200% 100%;
  animation: seq-shimmer 1.5s infinite;
}

.profile-menu {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.menu-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  background: none;
  border: none;
  border-radius: 10px;
  color: var(--text-dim);
  font-size: 0.95rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
  width: 100%;
  text-align: left;
  text-decoration: none;
}
.menu-item svg {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  opacity: 0.7;
  transition: opacity 0.2s ease;
}
.menu-item:hover {
  background: var(--surface-2);
  color: var(--text);
  transform: translateX(4px);
}
.menu-item:hover svg {
  opacity: 1;
}
.menu-item--danger {
  color: var(--danger);
  margin-top: 0.5rem;
}
.menu-item--danger:hover {
  background: var(--danger-dim);
  color: var(--danger);
}

/* Backdrop for mobile sidebar */
.sidebar-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
  z-index: 99;
}
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* ═══════════════════════════════════════════════════════════
   HEADER
   ═══════════════════════════════════════════════════════════ */
.hub-header {
  text-align: center;
  padding: 4rem 1.5rem 2.5rem;
  position: relative;
  z-index: 1;
  animation: seq-fade-up 0.6s ease-out;
}

.hub-logo {
  margin-bottom: 0.75rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.35rem;
}
.logo-bracket {
  color: var(--accent);
  font-size: 2rem;
  font-weight: 300;
  opacity: 0.7;
}
.logo-text {
  color: var(--text);
  font-size: 2.4rem;
  font-weight: 800;
  letter-spacing: 2px;
  text-shadow: 0 0 40px rgba(56, 189, 248, 0.15);
}
.hub-subtitle {
  color: var(--text-muted);
  font-size: 1.05rem;
  font-weight: 400;
  letter-spacing: 0.03em;
}
.hub-version {
  font-size: 0.72rem;
  color: var(--text-muted);
  margin-top: 0.75rem;
  font-family: var(--font-mono);
  opacity: 0.5;
}

/* ═══════════════════════════════════════════════════════════
   MODULE CARDS GRID
   ═══════════════════════════════════════════════════════════ */
.hub-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 1.5rem;
  max-width: 1100px;
  width: 100%;
  margin: 0 auto;
  padding: 0 1.5rem 3rem;
  flex: 1;
  position: relative;
  z-index: 1;
  align-content: start;   /* no distribuir espacio sobrante entre filas */
  align-items: start;     /* las cards no se estiran verticalmente en su celda */
}

.module-card {
  position: relative;
  overflow: hidden;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 2rem;
  text-decoration: none;
  display: flex;
  flex-direction: column;
  min-height: 240px;
  max-height: 320px;
  animation: seq-fade-up 0.5s ease-out backwards;
  transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1),
              border-color 0.3s ease,
              box-shadow 0.3s ease;
  cursor: pointer;
  isolation: isolate;
}

/* Card hover — lift + glow */
.module-card:not(.module-disabled):hover {
  transform: translateY(-6px) scale(1.01);
  border-color: var(--border-med);
  box-shadow: 0 24px 48px rgba(0, 0, 0, 0.3),
              0 0 0 1px var(--accent-dim);
}

/* Glow orb behind card */
.card-glow {
  position: absolute;
  top: -40%;
  right: -30%;
  width: 250px;
  height: 250px;
  border-radius: 50%;
  opacity: 0;
  transition: opacity 0.5s ease;
  pointer-events: none;
  filter: blur(50px);
  z-index: -1;
}
.module-sentinel .card-glow {
  background: radial-gradient(circle, rgba(52, 211, 153, 0.2) 0%, transparent 70%);
}
.module-aegis .card-glow {
  background: radial-gradient(circle, rgba(167, 139, 250, 0.2) 0%, transparent 70%);
}
.module-acheron .card-glow {
  background: radial-gradient(circle, rgba(129, 140, 248, 0.15) 0%, transparent 70%);
}
.module-card:not(.module-disabled):hover .card-glow {
  opacity: 1;
}

/* Shine sweep on hover */
.card-shine {
  position: absolute;
  inset: 0;
  background: linear-gradient(
    105deg,
    transparent 40%,
    rgba(255, 255, 255, 0.03) 45%,
    rgba(255, 255, 255, 0.06) 50%,
    rgba(255, 255, 255, 0.03) 55%,
    transparent 60%
  );
  background-size: 200% 100%;
  background-position: 100% 0;
  opacity: 0;
  transition: opacity 0.3s ease, background-position 0s;
  pointer-events: none;
  z-index: 0;
}
.module-card:not(.module-disabled):hover .card-shine {
  opacity: 1;
  background-position: -100% 0;
  transition: opacity 0.3s ease, background-position 0.6s ease;
}

.card-icon {
  width: 52px;
  height: 52px;
  border-radius: 14px;
  background: var(--surface-2);
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 1.25rem;
  border: 1px solid var(--border);
  transition: all 0.3s ease;
  position: relative;
  z-index: 1;
}
.card-icon svg {
  width: 26px;
  height: 26px;
  transition: transform 0.3s ease;
}
.module-card:not(.module-disabled):hover .card-icon {
  border-color: var(--accent);
  box-shadow: 0 0 20px var(--accent-dim);
}
.module-card:not(.module-disabled):hover .card-icon svg {
  transform: scale(1.1);
}

.module-sentinel { --accent: #34d399; --accent-dim: rgba(52,211,153,0.12); }
.module-sentinel .card-icon svg { color: #34d399; }
.module-aegis    { --accent: #a78bfa; --accent-dim: rgba(167,139,250,0.12); }
.module-aegis .card-icon svg    { color: #a78bfa; }
.module-acheron  { --accent: #818cf8; --accent-dim: rgba(129,140,248,0.10); }
.module-acheron .card-icon svg  { color: #818cf8; }

.card-content {
  flex: 1;
  position: relative;
  z-index: 1;
}
.card-title {
  font-size: 1.35rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 0.5rem;
  letter-spacing: -0.01em;
}
.card-desc {
  font-size: 0.92rem;
  color: var(--text-muted);
  line-height: 1.6;
  margin-bottom: 1.25rem;
}

.card-meta {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.card-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.35rem 0.7rem;
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.03em;
}
.badge-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  animation: seq-pulse 2s ease-in-out infinite;
}
.card-badge--active {
  background: var(--success-dim);
  color: var(--success);
  border: 1px solid rgba(52, 211, 153, 0.2);
}
.card-badge--later {
  background: var(--warn-dim);
  color: var(--warn);
  border: 1px solid rgba(251, 191, 36, 0.2);
}

.card-count {
  font-size: 0.75rem;
  color: var(--text-muted);
  font-family: var(--font-mono);
}

.card-arrow {
  position: absolute;
  bottom: 1.5rem;
  right: 1.5rem;
  color: var(--text-muted);
  opacity: 0.5;
  transition: all 0.3s ease;
  z-index: 1;
}
.card-arrow svg {
  width: 20px;
  height: 20px;
}
.module-card:not(.module-disabled):hover .card-arrow {
  opacity: 1;
  color: var(--accent);
  transform: translateX(3px);
}

/* Disabled module */
.module-disabled {
  opacity: 0.45;
  pointer-events: none;
  cursor: default;
}
.wip-overlay {
  position: absolute;
  top: 0;
  right: 0;
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.65rem 0.85rem;
  color: var(--text-muted);
  font-size: 0.75rem;
  font-weight: 500;
  border-radius: 16px 0 16px 0;
  pointer-events: none;
}

/* ═══════════════════════════════════════════════════════════
   FOOTER
   ═══════════════════════════════════════════════════════════ */
.hub-footer {
  text-align: center;
  padding: 1.75rem;
  font-size: 0.8rem;
  color: var(--text-muted);
  border-top: 1px solid var(--border);
  position: relative;
  z-index: 1;
  letter-spacing: 0.03em;
}

/* ═══════════════════════════════════════════════════════════
   RESPONSIVE
   ═══════════════════════════════════════════════════════════ */
@media (max-width: 768px) {
  .hub-grid {
    grid-template-columns: 1fr;
    padding: 0 1rem 2rem;
    gap: 1rem;
  }
  .module-card {
    min-height: 200px;
    padding: 1.5rem;
  }
  .hub-header {
    padding: 3rem 1rem 1.5rem;
  }
  .logo-text {
    font-size: 2rem;
  }
  .profile-sidebar {
    width: 260px;
  }
}
</style>
