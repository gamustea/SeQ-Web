<template>
  <Teleport to="body">
    <div v-if="show" class="modal-overlay" @click.self="$emit('close')">
      <div class="modal">
        <div class="modal-header">
          <h3>Nuevo Usuario</h3>
          <button class="modal-close" @click="$emit('close')">&times;</button>
        </div>

        <form @submit.prevent="handleSubmit">
          <!-- Personal -->
          <div class="modal-section">
            <h4>Información personal</h4>
            <div class="form-row">
              <div class="form-group">
                <label for="cu-first">Nombre</label>
                <input id="cu-first" v-model="form.first_name" type="text" required class="input" />
              </div>
              <div class="form-group">
                <label for="cu-last">Apellido</label>
                <input id="cu-last" v-model="form.last_name" type="text" required class="input" />
              </div>
            </div>
          </div>

          <!-- Credentials -->
          <div class="modal-section">
            <h4>Credenciales</h4>
            <div class="form-row">
              <div class="form-group">
                <label for="cu-username">Usuario</label>
                <input id="cu-username" v-model="form.username" type="text" required class="input" />
              </div>
              <div class="form-group">
                <label for="cu-email">Email</label>
                <input id="cu-email" v-model="form.email" type="email" required class="input" />
              </div>
            </div>

            <div class="form-group" style="margin-top:0.75rem">
              <label for="cu-password">Contraseña</label>
              <div class="password-wrap">
                <input :id="'cu-password'" v-model="form.password" :type="pwVisible ? 'text' : 'password'" required class="input" placeholder="Mínimo 8 caracteres" />
                <button type="button" class="pw-toggle" @click="pwVisible = !pwVisible" tabindex="-1">
                  <svg v-if="pwVisible" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                  <svg v-else width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                </button>
              </div>
              <div v-if="form.password" class="pw-strength">
                <div class="strength-bar" :class="`strength--${strengthLevel}`">
                  <div class="strength-fill" :style="{ width: strengthPct + '%' }"></div>
                </div>
                <span class="strength-label">{{ strengthLabel }}</span>
              </div>
            </div>
          </div>

          <!-- Role -->
          <div v-if="auth.isRoot" class="modal-section">
            <h4>Rol</h4>
            <div class="form-group">
              <select v-model="form.role" class="input select">
                <option value="role_user">Usuario</option>
                <option value="role_admin">Administrador</option>
              </select>
            </div>
          </div>

          <p v-if="errorMsg" class="form-error">{{ errorMsg }}</p>

          <div class="modal-actions">
            <button type="button" class="btn btn--secondary" @click="$emit('close')">Cancelar</button>
            <button type="submit" class="btn btn--primary" :disabled="submitting">
              {{ submitting ? 'Creando…' : 'Crear Usuario' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { useAuthStore } from '@/stores/authStore'

defineProps({ show: { type: Boolean, default: false } })
const emit = defineEmits(['close', 'created'])
const auth = useAuthStore()

const form = reactive({ first_name: '', last_name: '', username: '', email: '', password: '', role: 'role_user' })
const pwVisible = ref(false)
const submitting = ref(false)
const errorMsg = ref('')

const strengthLevel = computed(() => {
  const p = form.password
  if (!p) return ''
  if (p.length < 8) return 'weak'
  if (p.length >= 10 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)) return 'strong'
  return 'medium'
})

const strengthPct = computed(() => ({ weak: 25, medium: 55, strong: 100 }[strengthLevel.value] || 0))

const strengthLabel = computed(() => ({ weak: 'Débil', medium: 'Media', strong: 'Fuerte' }[strengthLevel.value] || ''))

function reset() {
  Object.assign(form, { first_name: '', last_name: '', username: '', email: '', password: '', role: 'role_user' })
  pwVisible.value = false
  errorMsg.value = ''
}

async function handleSubmit() {
  errorMsg.value = ''
  if (form.password.length < 8) { errorMsg.value = 'La contraseña debe tener al menos 8 caracteres.'; return }
  submitting.value = true
  emit('created', { ...form })
}

defineExpose({ reset })
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; z-index: 100; background: rgba(0,0,0,.65); display: flex; align-items: center; justify-content: center; padding: 1.5rem; }
.modal { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; width: 100%; max-width: 520px; max-height: 90vh; overflow-y: auto; padding: 1.75rem; }
.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem; }
.modal-header h3 { font-size: 1.15rem; font-weight: 700; color: var(--text); margin: 0; }
.modal-close { background: none; border: none; font-size: 1.5rem; color: var(--text-muted); cursor: pointer; padding: 0 0.25rem; line-height: 1; }
.modal-close:hover { color: var(--text); }
.modal-section { margin-bottom: 1rem; }
.modal-section h4 { font-size: 0.85rem; font-weight: 600; color: var(--text-dim); margin: 0 0 0.5rem; }

.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
.form-group { display: flex; flex-direction: column; gap: 0.3rem; }
.form-group label { font-size: 0.78rem; font-weight: 600; color: var(--text-dim); }

.input {
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 0.5rem 0.65rem; color: var(--text); font-size: 0.88rem; outline: none; width: 100%; box-sizing: border-box; transition: border-color 0.2s;
}
.input:focus { border-color: var(--accent); }
.select { cursor: pointer; appearance: auto; }

.password-wrap { position: relative; }
.password-wrap .input { padding-right: 2.5rem; }
.pw-toggle { position: absolute; right: 0.5rem; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 0.2rem; display: flex; }
.pw-toggle:hover { color: var(--text); }

.pw-strength { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.3rem; }
.strength-bar { flex: 1; height: 5px; background: var(--border); border-radius: 3px; overflow: hidden; }
.strength-fill { height: 100%; border-radius: 3px; transition: width 0.25s, background 0.25s; }
.strength--weak .strength-fill { background: var(--danger); }
.strength--medium .strength-fill { background: var(--warn); }
.strength--strong .strength-fill { background: var(--success); }
.strength-label { font-size: 0.72rem; font-weight: 600; color: var(--text-muted); min-width: 42px; }

.form-error { color: var(--danger); font-size: 0.82rem; margin: 0.5rem 0; }

.modal-actions { display: flex; gap: 0.75rem; justify-content: flex-end; margin-top: 1.25rem; }

.btn {
  padding: 0.5rem 1.25rem; border-radius: 7px; font-size: 0.85rem; font-weight: 600;
  border: 1px solid transparent; cursor: pointer; transition: background 0.2s;
}
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn--primary { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.btn--primary:hover:not(:disabled) { filter: brightness(1.15); }
.btn--secondary { background: transparent; color: var(--text-dim); border-color: var(--border); }
.btn--secondary:hover { background: var(--border); color: var(--text); }
</style>
