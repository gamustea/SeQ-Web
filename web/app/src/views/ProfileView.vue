<template>
  <div class="profile-page">
    <Topbar title="Perfil de Usuario" />

    <main class="main">
      <!-- Loading -->
      <div v-if="store.loading" class="loading-block">
        <div class="skeleton skeleton--lg"></div>
      </div>

      <template v-else>
        <!-- Header -->
        <section class="profile-header">
          <div class="profile-avatar">{{ initials }}</div>
          <h1 class="profile-display-name">{{ store.profile.first_name }} {{ store.profile.last_name }}</h1>
          <p class="profile-username">@{{ store.profile.username }}</p>
        </section>

        <!-- Personal Info Form -->
        <section class="profile-section">
          <h2>Información Personal</h2>

          <form class="profile-form" @submit.prevent="handleProfileSubmit">
            <div class="form-row">
              <div class="form-group">
                <label for="first-name">Nombre</label>
                <input id="first-name" v-model="firstName" type="text" required class="input" placeholder="Tu nombre" />
              </div>
              <div class="form-group">
                <label for="last-name">Apellido</label>
                <input id="last-name" v-model="lastName" type="text" required class="input" placeholder="Tu apellido" />
              </div>
            </div>

            <div class="form-row">
              <div class="form-group">
                <label for="profile-email">Email</label>
                <input id="profile-email" type="email" :value="store.profile.email" disabled class="input input--disabled" />
              </div>
              <div class="form-group">
                <label for="profile-username">Usuario</label>
                <input id="profile-username" type="text" :value="store.profile.username" disabled class="input input--disabled" />
              </div>
            </div>

            <div class="form-actions">
              <button type="button" class="btn btn--secondary" @click="$router.push('/hub')">Cancelar</button>
              <button type="submit" class="btn btn--primary" :disabled="savingProfile">
                {{ savingProfile ? 'Guardando…' : 'Guardar Cambios' }}
              </button>
            </div>
          </form>
        </section>

        <!-- Password Form -->
        <section class="profile-section">
          <h2>Seguridad</h2>

          <form class="profile-form" @submit.prevent="handlePasswordSubmit">
            <div class="form-row form-row--single">
              <div class="form-group">
                <label for="current-pwd">Contraseña actual</label>
                <input id="current-pwd" v-model="currentPassword" type="password" required class="input" placeholder="••••••••" />
              </div>
            </div>

            <div class="form-row">
              <div class="form-group">
                <label for="new-pwd">Nueva contraseña</label>
                <input id="new-pwd" v-model="newPassword" type="password" required minlength="8" class="input" placeholder="Mínimo 8 caracteres" />
              </div>
              <div class="form-group">
                <label for="confirm-pwd">Confirmar contraseña</label>
                <input id="confirm-pwd" v-model="confirmPassword" type="password" required minlength="8" class="input" placeholder="Repite la contraseña" />
              </div>
            </div>

            <p v-if="passwordError" class="form-error">{{ passwordError }}</p>

            <div class="form-actions">
              <button type="submit" class="btn btn--danger" :disabled="savingPassword">
                {{ savingPassword ? 'Cambiando…' : 'Cambiar Contraseña' }}
              </button>
            </div>
          </form>
        </section>
      </template>
    </main>

    <StarBackground />
    <AppToast />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import { useProfileStore } from '@/stores/profileStore'
import { useAuthStore } from '@/stores/authStore'
import { useUtils } from '@/composables/useUtils'

const store = useProfileStore()
const auth = useAuthStore()
const router = useRouter()
const { getInitials } = useUtils()

const firstName = ref('')
const lastName = ref('')
const savingProfile = ref(false)

const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const savingPassword = ref(false)
const passwordError = ref('')

const initials = computed(() => getInitials(store.profile.first_name, store.profile.last_name))

onMounted(async () => {
  await store.loadProfile()
  firstName.value = store.profile.first_name
  lastName.value = store.profile.last_name
})

async function handleProfileSubmit() {
  if (!firstName.value.trim() || !lastName.value.trim()) return
  savingProfile.value = true
  await store.updateProfile(firstName.value.trim(), lastName.value.trim())
  savingProfile.value = false
}

async function handlePasswordSubmit() {
  passwordError.value = ''

  if (newPassword.value.length < 8) {
    passwordError.value = 'La contraseña debe tener al menos 8 caracteres.'
    return
  }
  if (newPassword.value !== confirmPassword.value) {
    passwordError.value = 'Las contraseñas no coinciden.'
    return
  }
  if (newPassword.value === currentPassword.value) {
    passwordError.value = 'La nueva contraseña debe ser diferente de la actual.'
    return
  }

  savingPassword.value = true
  const ok = await store.changePassword(newPassword.value)
  savingPassword.value = false

  if (ok) {
    currentPassword.value = ''
    newPassword.value = ''
    confirmPassword.value = ''
    setTimeout(() => auth.logout(), 2000)
  }
}
</script>

<style scoped>
.profile-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); }
.main { max-width: 640px; margin: 0 auto; padding: 2rem 1.25rem; }

.profile-header { text-align: center; margin-bottom: 2.5rem; }
.profile-avatar {
  width: 88px; height: 88px; border-radius: 50%; background: var(--accent);
  color: var(--bg); font-size: 2rem; font-weight: 700;
  display: flex; align-items: center; justify-content: center; margin: 0 auto 1rem;
}
.profile-display-name { font-size: 1.4rem; font-weight: 700; color: var(--text); margin: 0 0 0.25rem; }
.profile-username { font-size: 0.9rem; color: var(--text-muted); margin: 0; }

.profile-section {
  background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
  padding: 1.5rem; margin-bottom: 1.25rem;
}
.profile-section h2 { font-size: 1.05rem; font-weight: 600; margin: 0 0 1rem; color: var(--text); }

.profile-form { display: flex; flex-direction: column; gap: 1rem; }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.form-row--single { grid-template-columns: 1fr; }
.form-group { display: flex; flex-direction: column; gap: 0.35rem; }
.form-group label { font-size: 0.8rem; font-weight: 600; color: var(--text-dim); }

.input {
  background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
  padding: 0.6rem 0.75rem; color: var(--text); font-size: 0.9rem; outline: none; transition: border-color 0.2s;
}
.input:focus { border-color: var(--accent); }
.input--disabled { opacity: 0.55; cursor: not-allowed; }

.form-error { color: var(--danger); font-size: 0.82rem; margin: 0; }

.form-actions { display: flex; gap: 0.75rem; justify-content: flex-end; padding-top: 0.5rem; }

.btn {
  padding: 0.6rem 1.5rem; border-radius: 8px; font-size: 0.88rem; font-weight: 600;
  border: 1px solid transparent; cursor: pointer; transition: background 0.2s, opacity 0.2s;
}
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn--primary { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.btn--primary:hover:not(:disabled) { background: var(--accent-hover, var(--accent)); filter: brightness(1.1); }
.btn--secondary { background: transparent; color: var(--text-dim); border-color: var(--border); }
.btn--secondary:hover { background: var(--border); color: var(--text); }
.btn--danger { background: var(--danger); color: #fff; }
.btn--danger:hover:not(:disabled) { filter: brightness(1.15); }

.loading-block { padding: 4rem 0; display: flex; justify-content: center; }
.skeleton { background: var(--surface); border-radius: 8px; animation: pulse 1.4s ease-in-out infinite; }
.skeleton--lg { width: 100%; height: 280px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
</style>
