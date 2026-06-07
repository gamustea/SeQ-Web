<template>
  <div class="login-page">
    <!-- Ambient background layers -->
    <div class="bg-grid" aria-hidden="true"></div>
    <div class="bg-scanlines" aria-hidden="true"></div>
    <div class="bg-radar" aria-hidden="true">
      <div class="radar-sweep"></div>
    </div>
    <div class="bg-glow"></div>

    <!-- Giant watermark -->
    <div class="watermark" aria-hidden="true">
      <span class="watermark-text">SeQ</span>
      <span class="watermark-sub">SECURITY OPERATIONS</span>
    </div>

    <!-- Decorative side elements -->
    <div class="side-decor side-decor--left" aria-hidden="true">
      <div class="vline"></div>
      <div class="vline-dots">
        <span></span><span></span><span></span><span></span><span></span>
      </div>
      <div class="vline"></div>
    </div>
    <div class="side-decor side-decor--right" aria-hidden="true">
      <div class="vline"></div>
      <div class="vline-dots">
        <span></span><span></span><span></span><span></span><span></span>
      </div>
      <div class="vline"></div>
    </div>

    <!-- Main login card -->
    <div class="login-card">
      <div class="card-aura"></div>
      <div class="card-border"></div>

      <div class="terminal-bar">
        <div class="terminal-dots">
          <span class="dot dot-r"></span>
          <span class="dot dot-y"></span>
          <span class="dot dot-g"></span>
        </div>
        <span class="terminal-label">seq@platform: ~/login</span>
        <span class="terminal-status">
          <span class="status-pulse"></span>
          <span class="status-text">LIVE</span>
        </span>
      </div>

      <div class="login-body">
        <div class="logo-wrap">
          <span class="logo-bracket">[</span>
          <span class="logo-text" data-text="SeQ">SeQ</span>
          <span class="logo-bracket">]</span>
        </div>
        <h1 class="login-title">
          <span class="title-line">Security Operations</span>
          <span class="title-line">Platform</span>
        </h1>
        <p class="login-subtitle">Introduce tus credenciales de acceso</p>

        <div
          class="alert"
          :class="['alert-' + alertType, alertMsg ? 'visible' : '']"
          role="alert"
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
          >
            <template v-if="alertType === 'error'">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </template>
            <template v-else>
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
              <polyline points="22 4 12 14.01 9 11.01" />
            </template>
          </svg>
          <span>{{ alertMsg }}</span>
        </div>

        <form novalidate @submit.prevent="handleSubmit">
          <div class="form-group" :class="{ focused: usernameFocused }">
            <label for="username">
              <span class="label-text">Usuario</span>
              <span class="label-cursor" aria-hidden="true">_</span>
            </label>
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
                @focus="usernameFocused = true"
                @blur="usernameFocused = false"
              />
              <div class="input-glow"></div>
            </div>
          </div>

          <div class="form-group" :class="{ focused: passwordFocused }">
            <label for="password">
              <span class="label-text">Contraseña</span>
              <span class="label-cursor" aria-hidden="true">_</span>
            </label>
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
                @focus="passwordFocused = true"
                @blur="passwordFocused = false"
              />
              <div class="input-glow"></div>
              <button
                type="button"
                class="toggle-pw"
                @click="showPassword = !showPassword"
                :aria-label="showPassword ? 'Ocultar' : 'Mostrar'"
              >
                <svg
                  v-if="!showPassword"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                >
                  <path
                    d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"
                  />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                <svg
                  v-else
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="2"
                >
                  <path
                    d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"
                  />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              </button>
            </div>
          </div>

          <button
            type="submit"
            class="login-btn"
            :class="{ loading }"
            :disabled="loading"
          >
            <span class="btn-text">Iniciar sesión</span>
            <span class="btn-shine" aria-hidden="true"></span>
            <span class="spinner" aria-hidden="true"></span>
          </button>
        </form>

        <div class="login-meta">
          <div class="meta-divider" aria-hidden="true">
            <span></span>
            <span class="meta-diamond">◆</span>
            <span></span>
          </div>
          <p class="login-footer">
            <span class="footer-code">v2.5.1</span>
            <span class="footer-sep">|</span>
            <span>SeQ &copy; 2025</span>
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
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
const usernameFocused = ref(false)
const passwordFocused = ref(false)

async function handleSubmit() {
  alertMsg.value = ''
  usernameError.value = false
  passwordError.value = false

  const un = username.value.trim()
  const pw = password.value

  if (!un) {
    showAlert('El usuario es obligatorio.', 'error')
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
    loading.value = false
  }
}

function showAlert(msg, type = 'error') {
  alertMsg.value = msg
  alertType.value = type
}
</script>

<style scoped>
/* ─── Page shell ─── */
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
  position: relative;
  overflow: hidden;
  background: var(--bg);
}

/* ─── Animated background grid ─── */
.bg-grid {
  position: fixed;
  inset: -50%;
  z-index: 0;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(212,160,74,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(212,160,74,0.03) 1px, transparent 1px);
  background-size: 60px 60px;
  transform: perspective(600px) rotateX(60deg);
  animation: grid-drift 24s linear infinite;
  mask-image: radial-gradient(ellipse at center, black 20%, transparent 70%);
}
@keyframes grid-drift {
  0% { transform: perspective(600px) rotateX(60deg) translateY(0); }
  100% { transform: perspective(600px) rotateX(60deg) translateY(60px); }
}

/* ─── CRT scanlines ─── */
.bg-scanlines {
  position: fixed;
  inset: 0;
  z-index: 1;
  pointer-events: none;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,0,0,0.15) 2px,
    rgba(0,0,0,0.15) 4px
  );
  opacity: 0.4;
}

/* ─── Radar sweep ─── */
.bg-radar {
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  display: flex;
  align-items: center;
  justify-content: center;
}
.radar-sweep {
  width: 120vmax;
  height: 120vmax;
  border-radius: 50%;
  border: 1px solid rgba(212,160,74,0.04);
  position: relative;
  animation: radar-rotate 12s linear infinite;
}
.radar-sweep::before,
.radar-sweep::after {
  content: '';
  position: absolute;
  border-radius: 50%;
  inset: 0;
  border: 1px solid rgba(212,160,74,0.03);
}
.radar-sweep::before { transform: scale(0.66); }
.radar-sweep::after  { transform: scale(0.33); }
@keyframes radar-rotate {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}

/* ─── Ambient glow orbs ─── */
.bg-glow {
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  background:
    radial-gradient(circle at 15% 50%, rgba(212,160,74,0.06) 0%, transparent 45%),
    radial-gradient(circle at 85% 30%, rgba(76,183,130,0.04) 0%, transparent 40%);
}

/* ─── Giant watermark ─── */
.watermark {
  position: fixed;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  z-index: 0;
  pointer-events: none;
  text-align: center;
  user-select: none;
}
.watermark-text {
  display: block;
  font-family: var(--font-display);
  font-size: clamp(12rem, 35vw, 28rem);
  font-weight: 800;
  line-height: 0.85;
  letter-spacing: -0.04em;
  color: transparent;
  -webkit-text-stroke: 1px rgba(212,160,74,0.06);
  opacity: 0.35;
  animation: watermark-breathe 6s ease-in-out infinite;
}
.watermark-sub {
  display: block;
  font-family: var(--font-mono);
  font-size: clamp(0.7rem, 1.2vw, 1rem);
  letter-spacing: 1.2em;
  color: rgba(212,160,74,0.08);
  margin-top: 1rem;
  text-indent: 1.2em;
}
@keyframes watermark-breathe {
  0%, 100% { opacity: 0.25; transform: translate(-50%, -50%) scale(1); }
  50%      { opacity: 0.45; transform: translate(-50%, -50%) scale(1.03); }
}

/* ─── Side decorations ─── */
.side-decor {
  position: fixed;
  top: 50%;
  transform: translateY(-50%);
  z-index: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.6rem;
  pointer-events: none;
}
.side-decor--left { left: 2rem; }
.side-decor--right { right: 2rem; }
.vline {
  width: 1px;
  height: 80px;
  background: linear-gradient(to bottom, transparent, rgba(212,160,74,0.15), transparent);
}
.vline-dots {
  display: flex;
  flex-direction: column;
  gap: 6px;
  align-items: center;
}
.vline-dots span {
  width: 3px;
  height: 3px;
  border-radius: 50%;
  background: rgba(212,160,74,0.25);
  animation: dot-pulse 2s ease-in-out infinite;
}
.vline-dots span:nth-child(2) { animation-delay: 0.2s; }
.vline-dots span:nth-child(3) { animation-delay: 0.4s; }
.vline-dots span:nth-child(4) { animation-delay: 0.6s; }
.vline-dots span:nth-child(5) { animation-delay: 0.8s; }
@keyframes dot-pulse {
  0%, 100% { opacity: 0.2; transform: scale(0.8); }
  50%      { opacity: 1;   transform: scale(1.2); }
}

/* ─── Login card ─── */
.login-card {
  position: relative;
  z-index: 2;
  width: 100%;
  max-width: 420px;
  background: rgba(19, 20, 26, 0.65);
  border: 1px solid var(--border-solid);
  border-radius: 14px;
  overflow: hidden;
  backdrop-filter: blur(24px) saturate(1.2);
  box-shadow:
    0 32px 80px rgba(0,0,0,0.5),
    0 0 0 1px rgba(255,255,255,0.03) inset;
  animation: card-enter 0.9s cubic-bezier(0.16, 1, 0.3, 1) forwards;
}
@keyframes card-enter {
  from {
    opacity: 0;
    transform: translateY(30px) scale(0.97);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

/* Animated border glow */
.card-border {
  position: absolute;
  inset: -1px;
  border-radius: 14px;
  padding: 1px;
  background: linear-gradient(
    135deg,
    rgba(212,160,74,0.4) 0%,
    rgba(212,160,74,0) 25%,
    rgba(212,160,74,0) 50%,
    rgba(212,160,74,0) 75%,
    rgba(212,160,74,0.4) 100%
  );
  background-size: 300% 300%;
  animation: border-glow 6s ease infinite;
  mask:
    linear-gradient(#fff 0 0) content-box,
    linear-gradient(#fff 0 0);
  mask-composite: exclude;
  -webkit-mask-composite: xor;
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.6s ease;
}
.login-card:hover .card-border {
  opacity: 1;
}
@keyframes border-glow {
  0%, 100% { background-position: 0% 50%; }
  50%      { background-position: 100% 50%; }
}

/* Soft inner aura */
.card-aura {
  position: absolute;
  inset: 0;
  border-radius: 14px;
  pointer-events: none;
  box-shadow: inset 0 0 60px rgba(212,160,74,0.02);
}

/* ─── Terminal bar ─── */
.terminal-bar {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 0.6rem 1rem;
  background: rgba(255,255,255,0.015);
  border-bottom: 1px solid var(--border-solid);
  position: relative;
}
.terminal-dots {
  display: flex;
  gap: 5px;
}
.dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  box-shadow: 0 0 6px currentColor;
}
.dot-r { background: #d96c6c; color: #d96c6c; }
.dot-y { background: #d4a04a; color: #d4a04a; }
.dot-g { background: #4cb782; color: #4cb782; }

.terminal-label {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  color: var(--text-muted);
  flex: 1;
}

.terminal-status {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  font-family: var(--font-mono);
  font-size: 0.6rem;
  color: var(--success);
  letter-spacing: 0.08em;
}
.status-pulse {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: var(--success);
  box-shadow: 0 0 6px var(--success);
  animation: live-pulse 2s ease-in-out infinite;
}
@keyframes live-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%      { opacity: 0.4; transform: scale(0.7); }
}

/* ─── Login body ─── */
.login-body {
  padding: 2.5rem 2.25rem 2rem;
  position: relative;
}

/* Logo */
.logo-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.3rem;
  margin-bottom: 1rem;
  animation: fade-up 0.7s 0.15s cubic-bezier(0.16,1,0.3,1) both;
}
.logo-bracket {
  color: var(--accent);
  font-size: 1.7rem;
  font-weight: 300;
  opacity: 0.5;
  font-family: var(--font-mono);
}
.logo-text {
  color: var(--text);
  font-size: 2rem;
  font-weight: 800;
  font-family: var(--font-display);
  letter-spacing: 3px;
  position: relative;
}
.logo-text::after {
  content: attr(data-text);
  position: absolute;
  left: 0;
  top: 0;
  color: transparent;
  -webkit-text-stroke: 1px rgba(212,160,74,0.15);
  transform: translate(2px, 2px);
  pointer-events: none;
}

/* Title */
.login-title {
  text-align: center;
  margin-bottom: 0.4rem;
  font-family: var(--font-display);
  animation: fade-up 0.7s 0.25s cubic-bezier(0.16,1,0.3,1) both;
}
.title-line {
  display: block;
  font-size: 1rem;
  font-weight: 600;
  color: var(--text);
  letter-spacing: 0.04em;
  line-height: 1.4;
}
.title-line:last-child {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--accent);
  letter-spacing: 0.12em;
  text-transform: uppercase;
  opacity: 0.9;
}

.login-subtitle {
  text-align: center;
  font-size: 0.8rem;
  color: var(--text-muted);
  margin-bottom: 1.75rem;
  animation: fade-up 0.7s 0.35s cubic-bezier(0.16,1,0.3,1) both;
}

@keyframes fade-up {
  from { opacity: 0; transform: translateY(12px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* ─── Alert ─── */
.alert {
  border-radius: 8px;
  padding: 0.75rem 1rem;
  font-size: 0.82rem;
  margin-bottom: 1.25rem;
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  opacity: 0;
  transform: translateY(-4px);
  transition: opacity 0.3s ease, transform 0.3s ease;
  pointer-events: none;
  font-family: var(--font-body);
}
.alert.visible {
  opacity: 1;
  transform: translateY(0);
  pointer-events: auto;
  animation: fade-up 0.5s cubic-bezier(0.16,1,0.3,1) both;
}
.alert.alert-error {
  background: rgba(217,108,108,0.06);
  border: 1px solid rgba(217,108,108,0.2);
  color: #e09090;
  box-shadow: 0 0 20px rgba(217,108,108,0.06);
}
.alert.alert-success {
  background: rgba(76,183,130,0.06);
  border: 1px solid rgba(76,183,130,0.2);
  color: #6ed9a0;
  box-shadow: 0 0 20px rgba(76,183,130,0.06);
}
.alert svg {
  flex-shrink: 0;
  margin-top: 1px;
}

/* ─── Form ─── */
form {
  animation: fade-up 0.7s 0.45s cubic-bezier(0.16,1,0.3,1) both;
}

.form-group {
  margin-bottom: 1.2rem;
  position: relative;
}
.form-group label {
  display: flex;
  align-items: baseline;
  gap: 0.25rem;
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--text-dim);
  margin-bottom: 0.45rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  transition: color 0.25s ease;
}
.form-group.focused label {
  color: var(--accent);
}
.label-cursor {
  font-family: var(--font-mono);
  color: var(--accent);
  opacity: 0;
  transition: opacity 0.2s ease;
}
.form-group.focused .label-cursor {
  opacity: 1;
  animation: blink 1s step-end infinite;
}
@keyframes blink {
  0%, 100% { opacity: 1; }
  50%      { opacity: 0; }
}

.input-wrap {
  position: relative;
  display: flex;
  align-items: center;
}
.input-wrap input {
  flex: 1;
  width: 100%;
  padding: 0.8rem 1rem;
  padding-right: 2.6rem;
  background: rgba(27, 29, 38, 0.6);
  border: 1px solid var(--border-solid);
  border-radius: 10px;
  color: var(--text);
  font-size: 0.92rem;
  font-family: var(--font-body);
  outline: none;
  transition: border-color 0.3s ease, box-shadow 0.3s ease, background 0.3s ease;
}
.input-wrap input::placeholder {
  color: var(--text-muted);
  opacity: 0.25;
}
.input-wrap input:focus {
  border-color: rgba(212,160,74,0.4);
  background: rgba(27, 29, 38, 0.85);
  box-shadow: 0 0 0 3px rgba(212,160,74,0.08), 0 4px 20px rgba(0,0,0,0.2);
}
.input-wrap input.input-error {
  border-color: rgba(217,108,108,0.5);
  box-shadow: 0 0 0 3px rgba(217,108,108,0.08);
  animation: shake 0.4s ease-in-out;
}
.input-wrap input:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.input-glow {
  position: absolute;
  inset: -1px;
  border-radius: 10px;
  opacity: 0;
  transition: opacity 0.3s ease;
  pointer-events: none;
  background: linear-gradient(135deg, rgba(212,160,74,0.15), transparent 60%);
  mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  mask-composite: exclude;
  -webkit-mask-composite: xor;
  padding: 1px;
}
.input-wrap input:focus ~ .input-glow {
  opacity: 1;
}

@keyframes shake {
  0%, 100% { transform: translateX(0); }
  20% { transform: translateX(-4px); }
  40% { transform: translateX(4px); }
  60% { transform: translateX(-3px); }
  80% { transform: translateX(3px); }
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
  border-radius: 6px;
  transition: color 0.2s, background 0.2s;
}
.toggle-pw:hover {
  color: var(--accent);
  background: rgba(212,160,74,0.08);
}
.toggle-pw svg {
  display: block;
}

/* ─── Submit button ─── */
.login-btn {
  width: 100%;
  padding: 0.85rem;
  margin-top: 0.6rem;
  background: linear-gradient(135deg, var(--accent), #c08a30);
  color: #0b0c10;
  font-weight: 700;
  font-size: 0.9rem;
  font-family: var(--font-body);
  letter-spacing: 0.04em;
  border: none;
  border-radius: 10px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  position: relative;
  overflow: hidden;
  transition: transform 0.25s cubic-bezier(0.16,1,0.3,1),
              box-shadow 0.25s ease,
              opacity 0.2s ease;
  box-shadow:
    0 4px 20px rgba(212,160,74,0.25),
    0 0 0 1px rgba(212,160,74,0.15) inset;
}
.login-btn:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow:
    0 8px 30px rgba(212,160,74,0.35),
    0 0 0 1px rgba(212,160,74,0.2) inset;
}
.login-btn:active:not(:disabled) {
  transform: translateY(0);
}
.login-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.btn-shine {
  position: absolute;
  top: 0;
  left: -100%;
  width: 60%;
  height: 100%;
  background: linear-gradient(
    90deg,
    transparent,
    rgba(255,255,255,0.15),
    transparent
  );
  transform: skewX(-20deg);
  transition: none;
}
.login-btn:hover:not(:disabled) .btn-shine {
  animation: shine-sweep 0.8s ease forwards;
}
@keyframes shine-sweep {
  to { left: 150%; }
}

.btn-text {
  position: relative;
  z-index: 1;
}
.login-btn.loading .btn-text {
  opacity: 0;
}
.login-btn.loading .btn-shine {
  display: none;
}
.login-btn.loading .spinner {
  opacity: 1;
  visibility: visible;
}

.spinner {
  position: absolute;
  width: 20px;
  height: 20px;
  border: 2.5px solid rgba(11,12,16,0.12);
  border-top-color: #0b0c10;
  border-radius: 50%;
  animation: seq-spin 0.7s linear infinite;
  opacity: 0;
  visibility: hidden;
  transition: opacity 0.2s ease;
}

/* ─── Footer meta ─── */
.login-meta {
  margin-top: 1.75rem;
  animation: fade-up 0.7s 0.6s cubic-bezier(0.16,1,0.3,1) both;
}
.meta-divider {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  margin-bottom: 0.75rem;
}
.meta-divider span:first-child,
.meta-divider span:last-child {
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--border-solid), transparent);
}
.meta-diamond {
  color: rgba(212,160,74,0.2);
  font-size: 0.5rem;
  line-height: 1;
}

.login-footer {
  text-align: center;
  font-size: 0.68rem;
  color: var(--text-muted);
  font-family: var(--font-mono);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  letter-spacing: 0.04em;
}
.footer-code {
  color: var(--accent);
  opacity: 0.5;
}
.footer-sep {
  opacity: 0.3;
}

/* ─── Responsive ─── */
@media (max-width: 640px) {
  .login-page { padding: 1rem; }
  .login-body { padding: 2rem 1.5rem 1.75rem; }
  .login-card { max-width: 100%; }
  .side-decor { display: none; }
  .watermark-text { font-size: 10rem; opacity: 0.15; }
  .watermark-sub { display: none; }
}
</style>
