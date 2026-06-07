<template>
  <div class="hub-page">
    <StarBackground />

    <!-- Profile trigger -->
    <button class="profile-trigger" @click="profileOpen = !profileOpen" aria-label="Perfil">
      <div class="profile-avatar-mini">
        {{ profileInitials }}
      </div>
    </button>

    <!-- Profile dropdown -->
    <Transition name="drop">
      <div v-if="profileOpen" class="profile-drop" ref="dropRef">
        <div class="drop-header">
          <div class="drop-avatar">{{ profileInitials }}</div>
          <div class="drop-name-wrap">
            <h3 v-if="profileLoaded" class="drop-name">{{ profileName }}</h3>
            <div v-else class="skeleton-line"></div>
            <span class="drop-role">{{ roleLabel }}</span>
          </div>
        </div>
        <nav class="drop-menu">
          <router-link to="/profile" class="drop-item" @click="profileOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            Perfil
          </router-link>
          <router-link v-if="auth.isAdmin" to="/users" class="drop-item" @click="profileOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
            Usuarios
          </router-link>
          <router-link v-if="auth.isAdmin" to="/config" class="drop-item" @click="profileOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            Configuración
          </router-link>
          <router-link v-if="auth.isAdmin" to="/queue" class="drop-item" @click="profileOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="8" y1="9" x2="16" y2="9"/><line x1="8" y1="13" x2="14" y2="13"/></svg>
            Cola de Tareas
          </router-link>
          <div class="drop-divider"></div>
          <button class="drop-item drop-item--danger" @click="logout">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            Cerrar sesión
          </button>
        </nav>
      </div>
    </Transition>

    <!-- Backdrop -->
    <Transition name="fade">
      <div v-if="profileOpen" class="drop-backdrop" @click="profileOpen = false"></div>
    </Transition>

    <!-- Hero section -->
    <header class="hub-hero">
      <div class="hero-logo">
        <span class="hero-bracket">[</span>
        <span class="hero-text">SeQ</span>
        <span class="hero-bracket">]</span>
      </div>
      <p class="hero-sub">Security Operations Platform</p>
      <div class="hero-terminal">
        <TerminalConsole />
      </div>
    </header>

    <!-- Module cards -->
    <main class="hub-cards">
      <router-link to="/sentinel" class="card card-sentinel" style="animation-delay: 0.1s">
        <div class="card-bg"></div>
        <div class="card-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="11" cy="11" r="8"/>
            <path d="M21 21l-4.35-4.35"/>
            <path d="M11 8v3l2 2"/>
          </svg>
        </div>
        <h2 class="card-title">Sentinel</h2>
        <p class="card-desc">Escaneo de red, análisis de vulnerabilidades y generación de informes con IA.</p>
        <div class="card-meta">
          <span class="card-status status-active">
            <span class="status-dot"></span>
            Operativo
          </span>
          <span class="card-info">3 escáneres</span>
        </div>
      </router-link>

      <router-link to="/aegis" class="card card-aegis" style="animation-delay: 0.2s">
        <div class="card-bg"></div>
        <div class="card-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"/>
            <path d="M9 12l2 2 4-4"/>
          </svg>
        </div>
        <h2 class="card-title">Aegis</h2>
        <p class="card-desc">Newsletter de inteligencia de seguridad generada por IA para concienciación.</p>
        <div class="card-meta">
          <span class="card-status status-active">
            <span class="status-dot"></span>
            Operativo
          </span>
          <span class="card-info">Exporta MD / JSON</span>
        </div>
      </router-link>

      <router-link to="/iris" class="card card-iris" style="animation-delay: 0.3s">
        <div class="card-bg"></div>
        <div class="card-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M9 12l2 2 4-4"/>
          </svg>
        </div>
        <h2 class="card-title">Iris</h2>
        <p class="card-desc">Análisis de cabeceras de correo para detectar phishing mediante reglas de verificación.</p>
        <div class="card-meta">
          <span class="card-status status-active">
            <span class="status-dot"></span>
            Operativo
          </span>
          <span class="card-info">5 reglas de análisis</span>
        </div>
      </router-link>

      <div class="card card-acheron card-disabled" style="animation-delay: 0.4s">
        <div class="card-bg"></div>
        <div class="card-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            <circle cx="12" cy="16" r="1"/>
          </svg>
        </div>
        <h2 class="card-title">Acheron</h2>
        <p class="card-desc">Bóveda cifrada de credenciales y tarjetas para tu organización.</p>
        <div class="card-meta">
          <span class="card-status status-later">Pendiente</span>
        </div>
        <div class="card-wip">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          <span>Próximamente</span>
        </div>
      </div>
    </main>

    <footer class="hub-footer">
      SeQ Platform &mdash; Security Operations Suite
    </footer>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/authStore'
import { useProfileStore } from '@/stores/profileStore'
import StarBackground from '@/components/shared/StarBackground.vue'
import TerminalConsole from '@/components/shared/TerminalConsole.vue'

const auth = useAuthStore()
const profileStore = useProfileStore()

const profileOpen = ref(false)
const dropRef = ref(null)

const profileName = computed(() => {
  const fn = profileStore.profile.first_name
  const ln = profileStore.profile.last_name
  if (fn || ln) return `${fn} ${ln}`.trim()
  return auth.username() || 'Usuario'
})

const profileLoaded = computed(() => !!profileStore.profile.username)

const roleLabel = computed(() => {
  const r = profileStore.profile.role || auth.role
  if (r === 'role_root') return 'Root'
  if (r === 'role_admin') return 'Admin'
  return 'Usuario'
})

const profileInitials = computed(() => {
  const parts = profileName.value.split(' ')
  return parts.length >= 2
    ? (parts[0][0] + parts[1][0]).toUpperCase()
    : (parts[0]?.[0] || 'U').toUpperCase()
})

let clickOutside = null

onMounted(() => {
  console.log('[HubView] mounted, llamando loadProfile...')
  profileStore.loadProfile()
  clickOutside = (e) => {
    const d = dropRef.value
    const t = document.querySelector('.profile-trigger')
    if (d && t && !d.contains(e.target) && !t.contains(e.target)) {
      profileOpen.value = false
    }
  }
  document.addEventListener('click', clickOutside)
})

onUnmounted(() => {
  if (clickOutside) document.removeEventListener('click', clickOutside)
})

function logout() {
  profileOpen.value = false
  auth.logout()
}
</script>

<style scoped>
.hub-page {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  position: relative;
  overflow-x: hidden;
}

/* Profile trigger — top-right */
.profile-trigger {
  position: fixed;
  top: 1rem;
  right: 1.25rem;
  z-index: 51;
  cursor: pointer;
  background: none;
  border: none;
  padding: 0;
}
.profile-avatar-mini {
  width: 34px;
  height: 34px;
  border-radius: 50%;
  background: var(--accent-dim);
  border: 1.5px solid var(--border-med);
  color: var(--accent-bright);
  font-family: var(--font-body);
  font-size: 0.7rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.25s ease;
}
.profile-trigger:hover .profile-avatar-mini {
  border-color: var(--accent);
  box-shadow: 0 0 12px var(--accent-dim);
}

/* Profile dropdown */
.profile-drop {
  position: fixed;
  top: calc(1rem + 42px);
  right: 1.25rem;
  z-index: 51;
  width: 240px;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 10px;
  padding: 0.75rem;
  box-shadow: 0 16px 40px rgba(0,0,0,0.5);
  animation: seq-fade-up 0.15s ease-out;
}
.drop-enter-active,
.drop-leave-active {
  transition: opacity 0.12s ease, transform 0.12s ease;
}
.drop-enter-from,
.drop-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}
.drop-header {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  padding-bottom: 0.65rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 0.4rem;
}
.drop-avatar {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  background: var(--accent-dim);
  color: var(--accent-bright);
  font-size: 0.72rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.drop-name-wrap {
  flex: 1;
  min-width: 0;
}
.drop-name {
  font-size: 0.88rem;
  font-weight: 600;
  color: var(--text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.drop-role {
  font-size: 0.7rem;
  color: var(--text-muted);
}
.skeleton-line {
  width: 100px;
  height: 14px;
  border-radius: 4px;
  background: var(--surface-2);
  animation: seq-shimmer 1.5s infinite;
  background-size: 200% 100%;
  background-image: linear-gradient(90deg, var(--surface-2) 25%, var(--surface-3) 50%, var(--surface-2) 75%);
}

.drop-menu {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}
.drop-item {
  display: flex;
  align-items: center;
  gap: 0.55rem;
  padding: 0.5rem 0.6rem;
  border-radius: 6px;
  color: var(--text-dim);
  font-size: 0.8rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
  text-decoration: none;
  border: none;
  background: none;
  width: 100%;
  text-align: left;
}
.drop-item svg {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
  opacity: 0.5;
  transition: opacity 0.15s ease;
}
.drop-item:hover {
  background: var(--surface-2);
  color: var(--text);
}
.drop-item:hover svg { opacity: 0.8; }
.drop-item--danger { color: var(--danger); }
.drop-item--danger:hover { background: var(--danger-dim); }
.drop-divider {
  height: 1px;
  background: var(--border);
  margin: 0.25rem 0;
}

.drop-backdrop {
  position: fixed;
  inset: 0;
  z-index: 50;
  background: transparent;
}
.fade-enter-active,
.fade-leave-active { transition: opacity 0.15s ease; }
.fade-enter-from,
.fade-leave-to { opacity: 0; }

/* Hero */
.hub-hero {
  text-align: center;
  padding: 3.5rem 1.5rem 2.5rem;
  position: relative;
  z-index: 1;
  animation: seq-fade-up 0.6s ease-out;
}
.hero-logo {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.3rem;
  margin-bottom: 0.4rem;
}
.hero-bracket {
  color: var(--accent);
  font-size: 1.8rem;
  font-weight: 300;
  opacity: 0.5;
}
.hero-text {
  color: var(--text);
  font-size: 2.2rem;
  font-weight: 800;
  font-family: var(--font-display);
  letter-spacing: 3px;
}
.hero-sub {
  color: var(--text-muted);
  font-size: 0.9rem;
  font-weight: 400;
  letter-spacing: 0.05em;
  margin-bottom: 2rem;
}
.hero-terminal {
  display: flex;
  justify-content: center;
}

/* Cards */
.hub-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1.25rem;
  max-width: 1000px;
  width: 100%;
  margin: 0 auto;
  padding: 0 1.5rem 3rem;
  flex: 1;
  position: relative;
  z-index: 1;
  align-content: start;
}

.card {
  position: relative;
  overflow: hidden;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.75rem;
  text-decoration: none;
  display: flex;
  flex-direction: column;
  min-height: 220px;
  animation: seq-fade-up 0.5s ease-out backwards;
  transition: transform 0.3s cubic-bezier(0.16,1,0.3,1),
              border-color 0.3s ease;
  cursor: pointer;
  isolation: isolate;
}
.card-bg {
  position: absolute;
  top: 0;
  right: 0;
  width: 180px;
  height: 180px;
  border-radius: 50%;
  opacity: 0;
  transition: opacity 0.5s ease;
  pointer-events: none;
  filter: blur(60px);
  z-index: -1;
}
.card-sentinel .card-bg { background: radial-gradient(circle, rgba(76,183,130,0.15) 0%, transparent 70%); }
.card-aegis .card-bg    { background: radial-gradient(circle, rgba(96,128,224,0.15) 0%, transparent 70%); }
.card-iris .card-bg     { background: radial-gradient(circle, rgba(224,122,95,0.15) 0%, transparent 70%); }
.card-acheron .card-bg  { background: radial-gradient(circle, rgba(160,122,192,0.12) 0%, transparent 70%); }
.card:not(.card-disabled):hover {
  transform: translateY(-4px);
  border-color: var(--border-med);
  box-shadow: 0 20px 40px rgba(0,0,0,0.3);
}
.card:not(.card-disabled):hover .card-bg {
  opacity: 1;
}

.card-icon {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  background: var(--surface-2);
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 1rem;
  border: 1px solid var(--border);
  transition: all 0.3s ease;
  position: relative;
  z-index: 1;
}
.card-icon svg {
  width: 22px;
  height: 22px;
  transition: transform 0.3s ease;
}
.card:not(.card-disabled):hover .card-icon {
  border-color: var(--accent);
  box-shadow: 0 0 16px var(--accent-dim);
}
.card:not(.card-disabled):hover .card-icon svg {
  transform: scale(1.1);
}

.card-sentinel { --accent: #4cb782; --accent-dim: rgba(76,183,130,0.10); }
.card-sentinel .card-icon svg { color: #4cb782; }
.card-aegis    { --accent: #6080e0; --accent-dim: rgba(96,128,224,0.10); }
.card-aegis .card-icon svg    { color: #6080e0; }
.card-iris     { --accent: #e07a5f; --accent-dim: rgba(224,122,95,0.10); }
.card-iris .card-icon svg     { color: #e07a5f; }
.card-acheron  { --accent: #a07ac0; --accent-dim: rgba(160,122,192,0.08); }
.card-acheron .card-icon svg  { color: #a07ac0; }

.card-title {
  font-size: 1.15rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 0.4rem;
  font-family: var(--font-display);
  letter-spacing: 0.01em;
}
.card-desc {
  font-size: 0.82rem;
  color: var(--text-dim);
  line-height: 1.6;
  margin-bottom: 1rem;
  flex: 1;
}

.card-meta {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-wrap: wrap;
  position: relative;
  z-index: 1;
}
.card-status {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.25rem 0.6rem;
  border-radius: 6px;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.02em;
}
.status-dot {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
}
.status-active {
  background: var(--success-dim);
  color: var(--success);
  border: 1px solid rgba(76,183,130,0.15);
}
.status-later {
  background: var(--warn-dim);
  color: var(--warn);
  border: 1px solid rgba(212,160,74,0.15);
}
.card-info {
  font-size: 0.7rem;
  color: var(--text-muted);
  font-family: var(--font-mono);
}

.card-disabled {
  opacity: 0.4;
  pointer-events: none;
  cursor: default;
}
.card-wip {
  position: absolute;
  top: 0;
  right: 0;
  display: flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.55rem 0.7rem;
  color: var(--text-muted);
  font-size: 0.7rem;
  font-weight: 500;
  border-radius: 0 12px 0 12px;
  background: rgba(255,255,255,0.02);
  pointer-events: none;
}
.card-wip svg { width: 14px; height: 14px; }

/* Footer */
.hub-footer {
  text-align: center;
  padding: 1.5rem;
  font-size: 0.72rem;
  color: var(--text-muted);
  border-top: 1px solid var(--border);
  position: relative;
  z-index: 1;
  letter-spacing: 0.03em;
}

@media (max-width: 768px) {
  .hub-cards {
    grid-template-columns: 1fr;
    padding: 0 1rem 2rem;
    gap: 1rem;
  }
  .card {
    min-height: 190px;
    padding: 1.25rem;
  }
  .hub-hero {
    padding: 2.5rem 1rem 1.5rem;
  }
  .hero-text {
    font-size: 1.8rem;
  }
}
</style>
