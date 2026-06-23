<template>
  <div class="acheron-page" data-module="acheron">
    <StarBackground />
    <Topbar title="Acheron" badge="Bóveda cifrada" />

    <main class="acheron-main">
      <!-- ─────────────── Pantalla de desbloqueo ─────────────── -->
      <section v-if="!unlocked" class="unlock-wrap">
        <form class="unlock-card" @submit.prevent="unlock">
          <div class="unlock-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <rect x="3" y="11" width="18" height="11" rx="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>
          <h1 class="unlock-title">Desbloquear bóveda</h1>
          <p class="unlock-sub">
            El cifrado y descifrado ocurren <strong>en tu navegador</strong>. Tu contraseña
            maestra nunca se envía al servidor.
          </p>

          <label class="field">
            <span class="field-label">Contraseña maestra</span>
            <div class="field-input">
              <input
                ref="passwordInput"
                v-model="masterPassword"
                :type="showPassword ? 'text' : 'password'"
                autocomplete="off"
                spellcheck="false"
                placeholder="••••••••••••"
                :disabled="busy"
              />
              <button
                type="button" class="reveal-btn" tabindex="-1"
                :aria-label="showPassword ? 'Ocultar' : 'Mostrar'"
                @click="showPassword = !showPassword"
              >
                <svg v-if="showPassword" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
            </div>
          </label>

          <p v-if="error" class="unlock-error">{{ error }}</p>

          <button type="submit" class="unlock-btn" :disabled="busy || !masterPassword">
            <span v-if="busy" class="spinner" aria-hidden="true"></span>
            {{ busy ? 'Descifrando…' : 'Desbloquear' }}
          </button>
        </form>
      </section>

      <!-- ─────────────── Bóveda descifrada ─────────────── -->
      <section v-else class="vault-wrap">
        <header class="vault-head">
          <div class="vault-head-info">
            <h1 class="vault-title">Tu bóveda</h1>
            <span class="vault-count">{{ totalItems }} elementos · {{ algorithmLabel }}</span>
          </div>
          <button class="lock-btn" @click="lock">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Bloquear
          </button>
        </header>

        <p v-if="totalItems === 0" class="vault-empty">
          Tu bóveda está vacía. Añade elementos desde la app móvil de Acheron.
        </p>

        <div
          v-for="cat in nonEmptyCategories"
          :key="cat"
          class="vault-section"
        >
          <h2 class="section-title">
            {{ CATEGORY_LABELS[cat] }}
            <span class="section-count">{{ entries[cat].length }}</span>
          </h2>

          <div class="cards-grid">
            <article v-for="item in entries[cat]" :key="item.id" class="entry-card">
              <header class="entry-head">
                <h3 class="entry-title">{{ item.title || 'Sin título' }}</h3>
                <span class="entry-id">{{ item.id }}</span>
              </header>

              <dl class="entry-fields">
                <div v-for="field in FIELDS[cat]" :key="field" class="entry-field">
                  <dt>{{ FIELD_LABELS[field] || field }}</dt>
                  <dd>
                    <span class="field-value">
                      {{ isSecret(field) && !revealed.has(item.id) ? '••••••••' : item[field] }}
                    </span>
                    <button
                      v-if="isSecret(field)" type="button" class="icon-btn"
                      :aria-label="revealed.has(item.id) ? 'Ocultar' : 'Mostrar'"
                      @click="toggleReveal(item.id)"
                    >
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    </button>
                    <button type="button" class="icon-btn" aria-label="Copiar" @click="copy(item[field])">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    </button>
                  </dd>
                </div>
              </dl>
            </article>
          </div>
        </div>
      </section>
    </main>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import { useApi } from '@/composables/useApi'
import { useAuthStore } from '@/stores/authStore'
import { openVault, WrongPasswordError } from '@/acheron/vault.js'
import { STORABLE_FIELDS, STORABLE_CATEGORIES } from '@/acheron/storableFields.js'

const { apiFetch } = useApi()
const auth = useAuthStore()

const CATEGORY_LABELS = {
  accounts: 'Cuentas',
  creditcards: 'Tarjetas',
  securenotes: 'Notas seguras',
  identities: 'Identidades',
  bankaccounts: 'Cuentas bancarias',
  wifinetworks: 'Redes Wi-Fi',
  licenses: 'Licencias',
}

const FIELD_LABELS = {
  username: 'Usuario', domain: 'Dominio', password: 'Contraseña',
  cardHolderName: 'Titular', cardNumber: 'Número', expirationDate: 'Caducidad',
  postalCode: 'Código postal', cvv: 'CVV', content: 'Contenido',
  fullName: 'Nombre', email: 'Email', phone: 'Teléfono', address: 'Dirección',
  city: 'Ciudad', country: 'País', documentId: 'Documento',
  bankName: 'Banco', holder: 'Titular', iban: 'IBAN', swiftBic: 'SWIFT/BIC',
  accountNumber: 'Nº de cuenta', ssid: 'SSID', securityType: 'Seguridad',
  product: 'Producto', licenseKey: 'Clave', licensedTo: 'Licenciado a', version: 'Versión',
}

const SECRET_FIELDS = new Set([
  'password', 'cvv', 'cardNumber', 'content', 'licenseKey',
  'iban', 'accountNumber', 'swiftBic', 'documentId',
])

const FIELDS = STORABLE_FIELDS
const CATEGORIES = STORABLE_CATEGORIES

const masterPassword = ref('')
const showPassword = ref(false)
const busy = ref(false)
const error = ref('')
const unlocked = ref(false)
const passwordInput = ref(null)

const entries = reactive({})
const revealed = reactive(new Set())
let algorithm = null

const nonEmptyCategories = computed(() =>
  CATEGORIES.filter((c) => (entries[c] || []).length > 0),
)
const totalItems = computed(() =>
  CATEGORIES.reduce((n, c) => n + (entries[c] || []).length, 0),
)
const algorithmLabel = computed(() =>
  algorithm ? `${algorithm.transformation} · ${algorithm.kdf}` : '',
)

function isSecret(field) {
  return SECRET_FIELDS.has(field)
}

function toggleReveal(id) {
  if (revealed.has(id)) revealed.delete(id)
  else revealed.add(id)
}

async function copy(value) {
  try {
    await navigator.clipboard.writeText(value)
  } catch {
    /* clipboard no disponible: silencioso */
  }
}

async function unlock() {
  if (!masterPassword.value || busy.value) return
  busy.value = true
  error.value = ''
  try {
    const res = await apiFetch('/acheron/vault')
    if (!res) return // sesión expirada: useApi ya redirige
    if (res.status === 404) {
      error.value = 'Todavía no tienes ninguna bóveda. Crea una desde la app móvil.'
      return
    }
    if (!res.ok) {
      error.value = `No se pudo obtener la bóveda (error ${res.status}).`
      return
    }

    const vaultJson = await res.json()
    const vault = await openVault(vaultJson, masterPassword.value, auth.username())
    const decrypted = await vault.decryptAll()

    for (const cat of CATEGORIES) entries[cat] = decrypted[cat] || []
    algorithm = vaultJson.algorithm
    unlocked.value = true
  } catch (e) {
    if (e instanceof WrongPasswordError) {
      error.value = 'Contraseña maestra incorrecta.'
    } else {
      console.error('[Acheron] error al desbloquear:', e)
      error.value = 'No se pudo descifrar la bóveda.'
    }
  } finally {
    busy.value = false
  }
}

function lock() {
  // Limpiar todo el material sensible de memoria.
  masterPassword.value = ''
  showPassword.value = false
  revealed.clear()
  for (const cat of CATEGORIES) entries[cat] = []
  algorithm = null
  unlocked.value = false
  nextTick(() => passwordInput.value?.focus())
}

onMounted(() => passwordInput.value?.focus())
onBeforeUnmount(lock)
</script>

<style scoped>
.acheron-page {
  min-height: 100vh;
  background: var(--bg);
  padding-top: var(--topbar-h);
  position: relative;
}

.acheron-main {
  position: relative;
  z-index: 1;
  max-width: 1100px;
  margin: 0 auto;
  padding: 2rem 1.5rem 4rem;
}

/* ════════ Pantalla de desbloqueo ════════ */
.unlock-wrap {
  min-height: calc(100vh - var(--topbar-h));
  display: flex;
  align-items: center;
  justify-content: center;
}
.unlock-card {
  width: 100%;
  max-width: 420px;
  background: rgba(17, 18, 24, 0.7);
  backdrop-filter: blur(18px);
  -webkit-backdrop-filter: blur(18px);
  border: 1px solid rgba(160, 122, 192, 0.22);
  border-radius: 16px;
  padding: 2.25rem 2rem;
  text-align: center;
  box-shadow: 0 28px 64px rgba(0, 0, 0, 0.5);
}
.unlock-icon {
  width: 54px; height: 54px; margin: 0 auto 1.1rem;
  display: grid; place-items: center; border-radius: 14px;
  background: rgba(160, 122, 192, 0.12);
  border: 1px solid rgba(160, 122, 192, 0.28);
  color: #c4a0e0;
}
.unlock-icon svg { width: 26px; height: 26px; }
.unlock-title { font-family: var(--font-display); font-size: 1.5rem; color: var(--text); margin-bottom: 0.5rem; }
.unlock-sub { font-size: 0.85rem; color: var(--text-dim); line-height: 1.5; margin-bottom: 1.5rem; }
.unlock-sub strong { color: #c4a0e0; font-weight: 600; }

.field { display: block; text-align: left; margin-bottom: 1rem; }
.field-label {
  display: block; font-family: var(--font-mono); font-size: 0.66rem;
  text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted);
  margin-bottom: 0.4rem;
}
.field-input { position: relative; display: flex; align-items: center; }
.field-input input {
  width: 100%; padding: 0.7rem 2.6rem 0.7rem 0.85rem;
  background: rgba(0, 0, 0, 0.25); border: 1px solid var(--border-med);
  border-radius: 9px; color: var(--text); font-size: 0.95rem;
  font-family: var(--font-mono); transition: border-color 0.2s ease;
}
.field-input input:focus { outline: none; border-color: rgba(160, 122, 192, 0.55); }
.reveal-btn {
  position: absolute; right: 0.5rem; background: none; border: none;
  color: var(--text-muted); cursor: pointer; padding: 0.3rem;
  display: grid; place-items: center;
}
.reveal-btn:hover { color: #c4a0e0; }
.reveal-btn svg { width: 18px; height: 18px; }

.unlock-error {
  color: var(--danger); font-size: 0.82rem; margin-bottom: 0.9rem;
  background: var(--danger-dim); border: 1px solid rgba(217, 108, 108, 0.25);
  border-radius: 8px; padding: 0.55rem 0.7rem;
}
.unlock-btn {
  width: 100%; padding: 0.8rem; border: none; border-radius: 9px;
  background: linear-gradient(135deg, #a07ac0, #7d5aa0); color: #fff;
  font-size: 0.95rem; font-weight: 600; cursor: pointer;
  display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem;
  transition: filter 0.2s ease, opacity 0.2s ease;
}
.unlock-btn:hover:not(:disabled) { filter: brightness(1.1); }
.unlock-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.spinner {
  width: 15px; height: 15px; border-radius: 50%;
  border: 2px solid rgba(255, 255, 255, 0.35); border-top-color: #fff;
  animation: spin 0.7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ════════ Bóveda descifrada ════════ */
.vault-head {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 1.75rem; gap: 1rem; flex-wrap: wrap;
}
.vault-title { font-family: var(--font-display); font-size: 1.7rem; color: var(--text); }
.vault-count {
  font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);
  letter-spacing: 0.04em;
}
.lock-btn {
  display: inline-flex; align-items: center; gap: 0.45rem;
  padding: 0.55rem 1rem; border-radius: 9px; cursor: pointer;
  background: rgba(160, 122, 192, 0.1); border: 1px solid rgba(160, 122, 192, 0.3);
  color: #c4a0e0; font-size: 0.82rem; font-weight: 600;
  transition: background 0.2s ease;
}
.lock-btn:hover { background: rgba(160, 122, 192, 0.18); }
.lock-btn svg { width: 15px; height: 15px; }

.vault-empty { color: var(--text-dim); font-size: 0.95rem; text-align: center; padding: 3rem 0; }

.vault-section { margin-bottom: 2rem; }
.section-title {
  display: flex; align-items: center; gap: 0.55rem;
  font-family: var(--font-mono); font-size: 0.78rem; text-transform: uppercase;
  letter-spacing: 0.1em; color: #c4a0e0; margin-bottom: 0.9rem;
  padding-bottom: 0.5rem; border-bottom: 1px solid rgba(160, 122, 192, 0.15);
}
.section-count {
  background: rgba(160, 122, 192, 0.15); color: #c4a0e0;
  border-radius: 20px; padding: 0.05rem 0.5rem; font-size: 0.68rem;
}

.cards-grid {
  display: grid; gap: 0.9rem;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
}
.entry-card {
  background: rgba(17, 18, 24, 0.6);
  border: 1px solid var(--border); border-radius: 12px;
  padding: 1.1rem 1.2rem; transition: border-color 0.2s ease;
}
.entry-card:hover { border-color: rgba(160, 122, 192, 0.3); }
.entry-head {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 0.5rem; margin-bottom: 0.8rem;
}
.entry-title { font-size: 1.05rem; font-weight: 600; color: var(--text); }
.entry-id { font-family: var(--font-mono); font-size: 0.62rem; color: var(--text-muted); }

.entry-fields { display: flex; flex-direction: column; gap: 0.55rem; }
.entry-field { display: flex; flex-direction: column; gap: 0.15rem; }
.entry-field dt {
  font-family: var(--font-mono); font-size: 0.6rem; text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--text-muted);
}
.entry-field dd { display: flex; align-items: center; gap: 0.4rem; }
.field-value {
  font-size: 0.88rem; color: var(--text); word-break: break-all;
  font-family: var(--font-mono); flex: 1;
}
.icon-btn {
  background: none; border: none; color: var(--text-muted); cursor: pointer;
  padding: 0.2rem; display: grid; place-items: center; flex-shrink: 0;
  transition: color 0.15s ease;
}
.icon-btn:hover { color: #c4a0e0; }
.icon-btn svg { width: 14px; height: 14px; }

@media (max-width: 640px) {
  .acheron-main { padding: 1.25rem 1rem 3rem; }
  .cards-grid { grid-template-columns: 1fr; }
}
</style>
