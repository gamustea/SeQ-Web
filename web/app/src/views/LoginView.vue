<template>
  <div class="login-page">
    <!-- Ambient glow background -->
    <div class="ambient-glow"></div>
    <div class="ambient-glow-2"></div>

    <!-- Loading overlay -->
    <Transition name="fade">
      <div v-if="loading" class="loading-overlay">
        <div class="loading-spinner"></div>
        <span class="loading-text">Autenticando…</span>
      </div>
    </Transition>

    <main class="card" role="main">
      <div class="logo-wrap">
        <img :src="'/resources/images/SecOps-Logo-BlueDark.png'" alt="SecOps Logo" />
      </div>

      <h1 class="card-title">Bienvenido a SecOps</h1>
      <p class="card-subtitle">Introduce tus credenciales para acceder a la plataforma</p>

      <!-- Alert using shared.css classes with Vue reactivity -->
      <div class="alert" :class="['alert-' + alertType, alertMsg ? 'visible' : '']" role="alert">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
             fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <template v-if="alertType === 'error'">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </template>
          <template v-else>
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
          </template>
        </svg>
        <span>{{ alertMsg }}</span>
      </div>

      <form id="login-form" novalidate @submit.prevent="handleSubmit">
        <div class="form-group">
          <label for="username">Usuario</label>
          <div class="input-wrap">
            <input
              type="text"
              id="username"
              v-model="username"
              placeholder="nombre_de_usuario"
              autocomplete="username"
              required
              :class="{ 'input-error': usernameError }"
              :disabled="loading"
            />
          </div>
        </div>

        <div class="form-group">
          <label for="password">Contraseña</label>
          <div class="input-wrap">
            <input
              :type="showPassword ? 'text' : 'password'"
              id="password"
              v-model="password"
              placeholder="••••••••"
              autocomplete="current-password"
              required
              :class="{ 'input-error': passwordError }"
              :disabled="loading"
            />
            <button
              type="button"
              class="toggle-pw"
              @click="showPassword = !showPassword"
              :aria-label="showPassword ? 'Ocultar contraseña' : 'Mostrar contraseña'"
            >
              <Transition name="icon-fade" mode="out-in">
                <svg v-if="!showPassword" key="eye" xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                     viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
                <svg v-else key="eye-off" xmlns="http://www.w3.org/2000/svg" width="20" height="20"
                     viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
                  <line x1="1" y1="1" x2="23" y2="23"/>
                </svg>
              </Transition>
            </button>
          </div>
        </div>

        <button
          type="submit"
          class="btn-login"
          :class="{ loading }"
          :disabled="loading"
        >
          <span class="btn-text">Iniciar sesión</span>
          <span class="spinner" aria-hidden="true"></span>
        </button>
      </form>

      <footer class="card-footer">
        SecOps &copy; 2025 — Security Operations Platform
      </footer>
    </main>
  </div>
</template>

<script setup>
/**
 * LoginView — Pantalla de inicio de sesión.
 *
 * Sustituye a la legacy login.html + login.js. Utiliza el store de autenticación
 * (authStore) para validar credenciales contra /oauth/token.
 */
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'

const router = useRouter()
const auth = useAuthStore()

const username = ref('')
const password = ref('')
const showPassword = ref(false)
const loading = ref(false)
const alertMsg = ref('')
const alertType = ref('error')
const usernameError = ref(false)
const passwordError = ref(false)

async function handleSubmit() {
  alertMsg.value = ''
  usernameError.value = false
  passwordError.value = false

  const un = username.value.trim()
  const pw = password.value

  if (!un) {
    showAlert('El nombre de usuario es obligatorio.', 'error')
    usernameError.value = true
    document.getElementById('username')?.focus()
    return
  }
  if (!pw) {
    showAlert('La contraseña es obligatoria.', 'error')
    passwordError.value = true
    document.getElementById('password')?.focus()
    return
  }

  loading.value = true
  try {
    await auth.login(un, pw)
    showAlert('Sesión iniciada. Redirigiendo…', 'success')
    setTimeout(() => router.push('/hub'), 900)
  } catch (err) {
    showAlert(err.message || 'Error desconocido.', 'error')
    if (err.message?.includes('Credenciales')) {
      usernameError.value = true
      passwordError.value = true
      password.value = ''
    }
  } finally {
    // loading se mantiene hasta el redirect para evitar doble-submit
  }
}

function showAlert(msg, type = 'error') {
  alertMsg.value = msg
  alertType.value = type
}
</script>

<style scoped>
/* ═══════════════════════════════════════════════════════════
   LOGIN PAGE — Ambient background
   ═══════════════════════════════════════════════════════════ */
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2rem;
  position: relative;
  overflow: hidden;
  background: var(--bg);
}

/* Glow orbs behind the card */
.ambient-glow,
.ambient-glow-2 {
  position: absolute;
  border-radius: 50%;
  filter: blur(100px);
  pointer-events: none;
  opacity: 0.35;
  animation: glow-pulse 6s ease-in-out infinite;
}
.ambient-glow {
  width: 500px;
  height: 500px;
  background: radial-gradient(circle, var(--accent-dim) 0%, transparent 70%);
  top: -10%;
  left: -10%;
}
.ambient-glow-2 {
  width: 400px;
  height: 400px;
  background: radial-gradient(circle, var(--accent-dim) 0%, transparent 70%);
  bottom: -10%;
  right: -10%;
  animation-delay: -3s;
}
@keyframes glow-pulse {
  0%, 100% { transform: scale(1); opacity: 0.3; }
  50%      { transform: scale(1.15); opacity: 0.45; }
}

/* ═══════════════════════════════════════════════════════════
   CARD — Main login container
   ═══════════════════════════════════════════════════════════ */
.card {
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 480px;
  padding: 3rem 2.5rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  text-align: center;
  animation: seq-fade-up 0.6s ease-out;
  box-shadow: 0 24px 64px rgba(0, 0, 0, 0.35),
              0 0 0 1px rgba(56, 189, 248, 0.06);
  transition: box-shadow 0.3s ease;
}
.card:hover {
  box-shadow: 0 28px 72px rgba(0, 0, 0, 0.4),
              0 0 0 1px rgba(56, 189, 248, 0.1);
}

.logo-wrap {
  margin-bottom: 2rem;
  display: flex;
  justify-content: center;
}
.logo-wrap img {
  height: 56px;
  filter: drop-shadow(0 4px 12px rgba(56, 189, 248, 0.15));
  transition: filter 0.3s ease, transform 0.3s ease;
}
.card:hover .logo-wrap img {
  filter: drop-shadow(0 6px 18px rgba(56, 189, 248, 0.25));
  transform: scale(1.03);
}

.card-title {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 0.4rem;
  letter-spacing: -0.01em;
}
.card-subtitle {
  font-size: 0.95rem;
  color: var(--text-dim);
  margin-bottom: 1.75rem;
  line-height: 1.5;
}
.card-footer {
  margin-top: 2rem;
  font-size: 0.78rem;
  color: var(--text-muted);
  letter-spacing: 0.02em;
}

/* ═══════════════════════════════════════════════════════════
   FORM
   ═══════════════════════════════════════════════════════════ */
.form-group {
  text-align: left;
  margin-bottom: 1.25rem;
}
.form-group label {
  display: block;
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text-dim);
  margin-bottom: 0.5rem;
  padding-left: 0.15rem;
}

.input-wrap {
  position: relative;
  display: flex;
  align-items: center;
}
.input-wrap input {
  flex: 1;
  width: 100%;
  padding: 0.85rem 1rem;
  padding-right: 2.8rem;
  background: var(--surface-2);
  border: 1.5px solid var(--border-solid);
  border-radius: 10px;
  color: var(--text);
  font-size: 1rem;
  outline: none;
  transition: border-color 0.25s ease, box-shadow 0.25s ease, transform 0.2s ease;
}
.input-wrap input::placeholder {
  color: var(--text-muted);
  opacity: 0.45;
}
.input-wrap input:hover {
  border-color: rgba(56, 189, 248, 0.25);
}
.input-wrap input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 4px var(--accent-dim), 0 0 20px rgba(56, 189, 248, 0.08);
  transform: translateY(-1px);
}
.input-wrap input.input-error {
  border-color: var(--danger);
  box-shadow: 0 0 0 3px var(--danger-dim);
  animation: shake 0.4s ease;
}
.input-wrap input.input-error:focus {
  box-shadow: 0 0 0 4px var(--danger-dim);
}
.input-wrap input:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

@keyframes shake {
  0%, 100% { transform: translateX(0); }
  20%, 60% { transform: translateX(-5px); }
  40%, 80% { transform: translateX(5px); }
}

.toggle-pw {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  background: none;
  border: none;
  color: var(--text-muted);
  cursor: pointer;
  padding: 6px;
  display: flex;
  align-items: center;
  border-radius: 6px;
  transition: color 0.2s ease, background 0.2s ease;
}
.toggle-pw:hover {
  color: var(--accent);
  background: var(--accent-dim);
}
.toggle-pw svg {
  display: block;
}

/* Icon transition */
.icon-fade-enter-active,
.icon-fade-leave-active {
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.icon-fade-enter-from,
.icon-fade-leave-to {
  opacity: 0;
  transform: scale(0.8);
}

/* ═══════════════════════════════════════════════════════════
   BUTTON
   ═══════════════════════════════════════════════════════════ */
.btn-login {
  width: 100%;
  padding: 0.9rem;
  margin-top: 0.75rem;
  background: linear-gradient(135deg, var(--accent) 0%, var(--accent-bright) 100%);
  color: #000;
  font-weight: 700;
  font-size: 1rem;
  border: none;
  border-radius: 10px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  position: relative;
  overflow: hidden;
  transition: transform 0.2s ease, box-shadow 0.2s ease, opacity 0.2s ease;
  box-shadow: 0 4px 16px rgba(56, 189, 248, 0.25);
}
.btn-login::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, transparent 0%, rgba(255,255,255,0.15) 100%);
  opacity: 0;
  transition: opacity 0.3s ease;
}
.btn-login:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(56, 189, 248, 0.35);
}
.btn-login:hover:not(:disabled)::before {
  opacity: 1;
}
.btn-login:active:not(:disabled) {
  transform: translateY(0);
  box-shadow: 0 2px 8px rgba(56, 189, 248, 0.2);
}
.btn-login:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none !important;
}

.btn-login.loading .btn-text {
  opacity: 0;
}
.btn-login.loading .spinner {
  opacity: 1;
  visibility: visible;
}

.spinner {
  position: absolute;
  width: 20px;
  height: 20px;
  border: 2.5px solid rgba(0,0,0,0.15);
  border-top-color: #000;
  border-radius: 50%;
  animation: seq-spin 0.7s linear infinite;
  opacity: 0;
  visibility: hidden;
  transition: opacity 0.2s ease;
}

/* ═══════════════════════════════════════════════════════════
   LOADING OVERLAY
   ═══════════════════════════════════════════════════════════ */
.loading-overlay {
  position: fixed;
  inset: 0;
  z-index: 100;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 1.25rem;
  background: rgba(8, 12, 20, 0.7);
  backdrop-filter: blur(12px);
}
.loading-spinner {
  width: 48px;
  height: 48px;
  border: 3px solid rgba(56, 189, 248, 0.15);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: seq-spin 0.8s linear infinite;
}
.loading-text {
  font-size: 1rem;
  color: var(--text-dim);
  font-weight: 500;
  letter-spacing: 0.05em;
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
   RESPONSIVE
   ═══════════════════════════════════════════════════════════ */
@media (max-width: 520px) {
  .login-page {
    padding: 1rem;
    align-items: flex-start;
    padding-top: 10vh;
  }
  .card {
    padding: 2rem 1.5rem;
    max-width: 100%;
  }
  .card-title {
    font-size: 1.3rem;
  }
  .input-wrap input {
    font-size: 0.95rem;
    padding: 0.75rem 0.9rem;
    padding-right: 2.6rem;
  }
}
</style>
