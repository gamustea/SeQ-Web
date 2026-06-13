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

    <Transition name="fade">
      <div v-if="profileOpen" class="drop-backdrop" @click="profileOpen = false"></div>
    </Transition>

    <!-- Main dashboard -->
    <main class="hub-dashboard">
      <!-- Left column -->
      <section class="hub-left" style="animation-delay: 0.1s">
        <div class="hero-block">
          <div class="hero-head">
            <img :src="seqLogo" alt="SeQ" class="hero-logo-img" />
            <div class="hero-head-body">
              <div class="hero-logo">
                <span class="hero-bracket hero-bracket--left">[</span>
                <span class="hero-text">SeQ</span>
                <span class="hero-bracket hero-bracket--right">]</span>
              </div>
              <div class="hero-sub">
                <span class="hero-sub-badge">Security Operations Platform</span>
              </div>
            </div>
          </div>
          <div class="hero-divider"></div>
        </div>

        <div class="hub-terminal" style="animation-delay: 0.2s">
          <TerminalConsole />
        </div>

        <div class="hub-quickstats" style="animation-delay: 0.3s">
          <a href="https://github.com/gamustea/SeQ" target="_blank" rel="noopener noreferrer" class="stat-tile stat-tile--link">
            <div class="stat-icon stat-icon--github">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
              </svg>
            </div>
            <div class="stat-body">
              <span class="stat-value">gamustea/SeQ</span>
              <span class="stat-label">GitHub</span>
            </div>
          </a>
          <div class="stat-tile">
            <div class="stat-icon stat-icon--version">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
              </svg>
            </div>
            <div class="stat-body">
              <span class="stat-value">v3.0</span>
              <span class="stat-label">Versión</span>
            </div>
          </div>
        </div>
      </section>

      <!-- Right column: module cards grid -->
      <section class="hub-right">
        <router-link to="/sentinel" class="card card-sentinel" style="animation-delay: 0.25s">
          <div class="card-bg"></div>
          <div class="card-accent"></div>
          <div class="card-icon">
            <img :src="sentinelIcon" alt="Sentinel" class="card-icon-img" />
          </div>
          <div class="card-body">
            <h2 class="card-title">Sentinel</h2>
            <p class="card-desc">Escaneo de red, análisis de vulnerabilidades y generación de informes con IA.</p>
            <div class="card-meta">
              <span class="card-status status-active">
                <span class="status-dot"></span>
                Operativo
              </span>
              <span class="card-info">3 escáneres</span>
            </div>
          </div>
        </router-link>

        <router-link to="/aegis" class="card card-aegis" style="animation-delay: 0.33s">
          <div class="card-bg"></div>
          <div class="card-accent"></div>
          <div class="card-icon">
            <img :src="aegisIcon" alt="Aegis" class="card-icon-img" />
          </div>
          <div class="card-body">
            <h2 class="card-title">Aegis</h2>
            <p class="card-desc">Newsletter de inteligencia de seguridad generada por IA para concienciación.</p>
            <div class="card-meta">
              <span class="card-status status-active">
                <span class="status-dot"></span>
                Operativo
              </span>
              <span class="card-info">Exporta MD / JSON</span>
            </div>
          </div>
        </router-link>

        <router-link to="/iris" class="card card-iris" style="animation-delay: 0.41s">
          <div class="card-bg"></div>
          <div class="card-accent"></div>
          <div class="card-icon">
            <img :src="irisIcon" alt="Iris" class="card-icon-img" />
          </div>
          <div class="card-body">
            <h2 class="card-title">Iris</h2>
            <p class="card-desc">Análisis de cabeceras de correo para detectar phishing mediante reglas de verificación.</p>
            <div class="card-meta">
              <span class="card-status status-active">
                <span class="status-dot"></span>
                Operativo
              </span>
              <span class="card-info">5 reglas de análisis</span>
            </div>
          </div>
        </router-link>

        <div class="card card-acheron card-disabled" style="animation-delay: 0.49s">
          <div class="card-bg"></div>
          <div class="card-accent"></div>
          <div class="card-icon">
            <img :src="acheronIcon" alt="Acheron" class="card-icon-img" />
          </div>
          <div class="card-body">
            <h2 class="card-title">Acheron</h2>
            <p class="card-desc">Bóveda cifrada de credenciales y tarjetas para tu organización.</p>
            <div class="card-meta">
              <span class="card-status status-later">Pendiente</span>
            </div>
          </div>
          <div class="card-wip">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            <span>Próximamente</span>
          </div>
        </div>
      </section>
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

import sentinelIcon from '@/assets/images/sentinel/Sentinel-Turqoise-BgN.png'
import aegisIcon from '@/assets/images/aegis/SeQ-Aegis-Blue-BgN.png'
import irisIcon from '@/assets/images/iris/Iris-Red-BgN.png'
import acheronIcon from '@/assets/images/acheron/Acheron-Purple-BgN.png'
import seqLogo from '@/assets/images/seq/SeQ-BgN.png'

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
  height: 100vh;
  display: flex;
  flex-direction: column;
  position: relative;
  overflow: hidden;
}

/* ── Profile trigger ── */
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

/* ── Profile dropdown ── */
.profile-drop {
  position: fixed;
  top: calc(1rem + 42px);
  right: 1.25rem;
  z-index: 51;
  width: 250px;
  background: rgba(19,20,26,0.92);
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  border: 1px solid var(--border-solid);
  border-radius: 12px;
  padding: 0.8rem;
  box-shadow: 0 20px 48px rgba(0,0,0,0.55);
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
  padding-bottom: 0.7rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 0.4rem;
}
.drop-avatar {
  width: 38px;
  height: 38px;
  border-radius: 50%;
  background: var(--accent-dim);
  color: var(--accent-bright);
  font-size: 0.75rem;
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
  font-size: 0.9rem;
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

/* ── Dashboard grid ── */
.hub-dashboard {
  flex: 1;
  min-height: 0;
  display: grid;
  grid-template-columns: 2fr 1fr;
  grid-template-rows: 1fr;
  gap: 3rem;
  max-width: 1700px;
  width: 100%;
  margin: 0 auto;
  padding: 2.5rem 3rem 0;
  position: relative;
  z-index: 1;
}

/* ── Left column ── */
.hub-left {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
  animation: seq-fade-up 0.7s ease-out backwards;
  min-width: 0;
  min-height: 0;
  overflow-y: auto;
}

.hero-block {
  display: flex;
  flex-direction: column;
}

.hero-logo {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 0.5rem;
}

.hero-head {
  display: flex;
  align-items: center;
  gap: 1.2rem;
}
.hero-head-body {
  display: flex;
  flex-direction: column;
}
.hero-logo-img {
  height: 6rem;
  width: auto;
  display: block;
  flex-shrink: 0;
}
.hero-bracket {
  font-size: 4.2rem;
  font-weight: 200;
  font-family: var(--font-display);
  line-height: 1;
}
.hero-bracket--left {
  color: var(--accent);
  text-shadow: 0 0 40px var(--accent-dim), 0 0 80px rgba(212,160,74,0.06);
}
.hero-bracket--right {
  color: var(--accent);
  text-shadow: 0 0 40px var(--accent-dim), 0 0 80px rgba(212,160,74,0.06);
}

.hero-text {
  font-size: 4.2rem;
  font-weight: 800;
  font-family: var(--font-display);
  letter-spacing: 4px;
  line-height: 1;
  background: linear-gradient(135deg, var(--accent-bright) 0%, var(--text) 60%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.hero-sub {
  margin-top: 0.5rem;
}

.hero-sub-badge {
  display: inline-block;
  padding: 0.3rem 0.9rem;
  border-radius: 20px;
  background: rgba(255,255,255,0.03);
  border: 1px solid rgba(255,255,255,0.06);
  font-size: 0.7rem;
  font-weight: 500;
  color: var(--text-dim);
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.hero-divider {
  margin-top: 1.5rem;
  width: 100%;
  height: 1px;
  background: linear-gradient(90deg, var(--accent-dim), transparent 80%);
}

.hub-terminal {
  animation: seq-fade-up 0.7s ease-out backwards;
}

.hub-quickstats {
  display: flex;
  gap: 0.65rem;
  animation: seq-fade-up 0.7s ease-out backwards;
}

.stat-tile {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 0.55rem;
  padding: 0.65rem 0.8rem;
  background: rgba(19,20,26,0.55);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255,255,255,0.05);
  border-radius: 10px;
  transition: all 0.3s ease;
}
.stat-tile:hover {
  border-color: var(--border-med);
  background: rgba(19,20,26,0.75);
}

.stat-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.stat-icon svg { width: 15px; height: 15px; }
.stat-icon--scans  { background: rgba(76,183,130,0.12);  color: var(--success); }
.stat-icon--uptime { background: rgba(96,128,224,0.12);  color: var(--info); }
.stat-icon--version{ background: rgba(212,160,74,0.12); color: var(--accent); }
.stat-icon--github { background: rgba(255,255,255,0.06); color: var(--text-dim); }

.stat-tile--link {
  text-decoration: none;
  color: inherit;
  cursor: pointer;
}

.stat-body {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.stat-value {
  font-family: var(--font-mono);
  font-size: 0.85rem;
  font-weight: 700;
  color: var(--text);
  line-height: 1.2;
}
.stat-label {
  font-size: 0.6rem;
  font-weight: 500;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

/* ── Right column: module cards ── */
.hub-right {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  overflow-y: auto;
  min-height: 0;
  padding: 0.5rem 0.4rem 0.5rem 0;
}

.card {
  position: relative;
  overflow: hidden;
  background: rgba(19,20,26,0.55);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255,255,255,0.05);
  border-radius: 12px;
  padding: 1.5rem;
  text-decoration: none;
  display: flex;
  flex-direction: column;
  min-height: 260px;
  animation: seq-fade-up 0.6s ease-out backwards;
  transition: transform 0.4s cubic-bezier(0.16,1,0.3,1),
              border-color 0.3s ease,
              box-shadow 0.4s ease;
  cursor: pointer;
  isolation: isolate;
  perspective: 800px;
}

.card-accent {
  position: absolute;
  left: 0;
  top: 12%;
  bottom: 12%;
  width: 3px;
  border-radius: 0 3px 3px 0;
  transition: all 0.4s ease;
  z-index: 2;
}

.card-bg {
  position: absolute;
  top: 0;
  right: 0;
  width: 200px;
  height: 200px;
  border-radius: 50%;
  opacity: 0;
  transition: opacity 0.5s ease;
  pointer-events: none;
  filter: blur(70px);
  z-index: -1;
}

.card-sentinel .card-accent { background: #4cb782; box-shadow: 0 0 12px rgba(76,183,130,0.25); }
.card-sentinel .card-bg    { background: radial-gradient(circle, rgba(76,183,130,0.15) 0%, transparent 70%); }
.card-aegis .card-accent    { background: #6080e0; box-shadow: 0 0 12px rgba(96,128,224,0.25); }
.card-aegis .card-bg       { background: radial-gradient(circle, rgba(96,128,224,0.15) 0%, transparent 70%); }
.card-iris .card-accent     { background: #e07a5f; box-shadow: 0 0 12px rgba(224,122,95,0.25); }
.card-iris .card-bg        { background: radial-gradient(circle, rgba(224,122,95,0.15) 0%, transparent 70%); }
.card-acheron .card-accent  { background: #a07ac0; box-shadow: 0 0 12px rgba(160,122,192,0.15); }
.card-acheron .card-bg     { background: radial-gradient(circle, rgba(160,122,192,0.12) 0%, transparent 70%); }

.card:not(.card-disabled):hover {
  transform: translateY(-4px);
  border-color: rgba(255,255,255,0.10);
  box-shadow:
    0 24px 48px rgba(0,0,0,0.4),
    inset 4px 0 20px rgba(255,255,255,0.03);
}
.card:not(.card-disabled):hover .card-accent {
  width: 4px;
  box-shadow: 0 0 20px currentColor;
}
.card:not(.card-disabled):hover .card-bg {
  opacity: 1;
}

.card-icon {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  background: rgba(255,255,255,0.04);
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 1rem;
  border: 1px solid rgba(255,255,255,0.06);
  transition: all 0.35s ease;
  position: relative;
  z-index: 1;
}
.card-icon-img {
  width: 100%;
  height: 100%;
  object-fit: contain;
  display: block;
  transition: transform 0.35s ease;
}
.card:not(.card-disabled):hover .card-icon {
  border-color: rgba(255,255,255,0.12);
  box-shadow: 0 0 20px var(--accent-dim);
  background: rgba(255,255,255,0.06);
}
.card:not(.card-disabled):hover .card-icon-img {
  transform: scale(1.1);
}

.card-body {
  flex: 1;
  display: flex;
  flex-direction: column;
  position: relative;
  z-index: 1;
}

.card-title {
  font-size: 1.55rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 0.35rem;
  font-family: var(--font-display);
  letter-spacing: 0.02em;
}

.card-desc {
  font-size: 1.1rem;
  color: var(--text-dim);
  line-height: 1.6;
  margin-bottom: 0.9rem;
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
  padding: 0.2rem 0.65rem;
  border-radius: 5px;
  font-size: 0.9rem;
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
  font-size: 0.9rem;
  color: var(--text-muted);
  font-family: var(--font-mono);
}

.card-disabled {
  opacity: 0.38;
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
  padding: 0.5rem 0.75rem;
  color: var(--text-muted);
  font-size: 0.9rem;
  font-weight: 500;
  border-radius: 0 12px 0 12px;
  background: rgba(255,255,255,0.025);
  pointer-events: none;
  z-index: 2;
}
.card-wip svg { width: 15px; height: 15px; }

/* ── Footer ── */
.hub-footer {
  text-align: center;
  padding: 1.25rem;
  font-size: 0.7rem;
  color: var(--text-muted);
  border-top: 1px solid var(--border);
  position: relative;
  z-index: 1;
  letter-spacing: 0.04em;
}

/* ── Responsive ── */
@media (max-width: 1024px) {
  .hub-page {
    height: auto;
    min-height: 100vh;
    overflow: visible;
  }
  .hub-dashboard {
    grid-template-columns: 1fr;
    grid-template-rows: none;
    gap: 1.75rem;
    padding: 1.5rem 1.25rem 0;
    max-width: 700px;
    min-height: auto;
  }
  .hub-left,
  .hub-right {
    overflow-y: visible;
    min-height: auto;
  }
}

@media (max-width: 640px) {
  .hub-dashboard {
    padding: 1rem 1rem 0;
    gap: 1.25rem;
  }
  .hero-logo-img {
    height: 4rem;
  }
  .hero-head {
    gap: 0.8rem;
  }
  .hero-text {
    font-size: 2.8rem;
    letter-spacing: 2px;
  }
  .hero-bracket {
    font-size: 2.8rem;
  }
  .hero-sub-badge {
    font-size: 0.62rem;
  }
  .hub-quickstats {
    flex-direction: column;
    gap: 0.5rem;
  }
  .card {
    min-height: 200px;
    padding: 1.2rem;
  }
}
</style>
