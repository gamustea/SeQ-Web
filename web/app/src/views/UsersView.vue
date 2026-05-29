<template>
  <div class="users-page">
    <Topbar title="Gestión de Usuarios" />

    <main class="main">
      <!-- Header -->
      <div class="page-header">
        <div>
          <h1>Usuarios</h1>
          <p class="subtitle">Administra los usuarios y sus atributos ABAC</p>
        </div>
        <div class="header-right">
          <span class="user-count">{{ store.users.length }} usuario(s)</span>
          <button class="btn btn--primary" @click="showCreateModal = true">+ Nuevo Usuario</button>
        </div>
      </div>

      <!-- Loading -->
      <div v-if="store.loading" class="loading-block">
        <div class="skeleton skeleton--card" v-for="i in 3" :key="i"></div>
      </div>

      <!-- Root Section -->
      <section v-if="store.grouped.root.length" class="role-section">
        <h2 class="role-heading role-heading--root">Root ({{ store.grouped.root.length }})</h2>
        <div class="card-grid">
          <UserCard v-for="u in store.grouped.root" :key="u.id" :user="u" @details="openDetails(u.id)" />
        </div>
      </section>

      <!-- Admin Section -->
      <section v-if="store.grouped.admin.length" class="role-section">
        <h2 class="role-heading role-heading--admin">Administradores ({{ store.grouped.admin.length }})</h2>
        <div class="card-grid">
          <UserCard v-for="u in store.grouped.admin" :key="u.id" :user="u" @details="openDetails(u.id)" />
        </div>
      </section>

      <!-- User Section -->
      <section v-if="store.grouped.user.length" class="role-section">
        <h2 class="role-heading role-heading--user">Usuarios ({{ store.grouped.user.length }})</h2>
        <div class="card-grid">
          <UserCard v-for="u in store.grouped.user" :key="u.id" :user="u" @details="openDetails(u.id)" />
        </div>
      </section>

      <!-- Empty -->
      <div v-if="!store.loading && store.users.length === 0" class="empty-state">
        No hay usuarios registrados.
      </div>
    </main>

    <!-- Modals -->
    <CreateUserModal :show="showCreateModal" @close="showCreateModal = false" @created="handleCreateUser" ref="createModal" />
    <UserDetailsModal :show="showDetailsModal" :user-id="selectedUserId" @close="showDetailsModal = false" @refresh="store.loadUsers()" />

    <StarBackground />
    <AppToast />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import { useUsersStore } from '@/stores/usersStore'
import UserCard from '@/components/users/UserCard.vue'
import CreateUserModal from '@/components/users/CreateUserModal.vue'
import UserDetailsModal from '@/components/users/UserDetailsModal.vue'

const store = useUsersStore()

const showCreateModal = ref(false)
const showDetailsModal = ref(false)
const selectedUserId = ref(null)
const createModal = ref(null)

onMounted(() => store.loadUsers())

function openDetails(userId) {
  selectedUserId.value = userId
  showDetailsModal.value = true
}

async function handleCreateUser(userData) {
  const ok = await store.createUser(userData)
  if (ok) {
    showCreateModal.value = false
    createModal.value?.reset()
  }
}
</script>

<style scoped>
.users-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); }
.main { max-width: 960px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }

.page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem; }
.page-header h1 { font-size: 1.6rem; font-weight: 800; color: var(--text); margin: 0; }
.subtitle { font-size: 0.88rem; color: var(--text-dim); margin: 0.25rem 0 0; }
.header-right { display: flex; align-items: center; gap: 1rem; }
.user-count { font-size: 0.82rem; color: var(--text-muted); font-family: var(--font-mono); }

.role-section { margin-bottom: 2rem; }
.role-heading { font-size: 0.95rem; font-weight: 700; margin: 0 0 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; }
.role-heading--root  { color: var(--danger); }
.role-heading--admin { color: var(--warn); }
.role-heading--user  { color: var(--info); }

.card-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 0.75rem; }

.empty-state { text-align: center; padding: 4rem 0; color: var(--text-muted); font-size: 0.95rem; }

.btn {
  padding: 0.6rem 1.4rem; border-radius: 8px; font-size: 0.88rem; font-weight: 600;
  border: 1px solid transparent; cursor: pointer; transition: background 0.2s;
}
.btn--primary { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.btn--primary:hover { filter: brightness(1.15); }

.loading-block { display: flex; flex-direction: column; gap: 0.75rem; padding: 2rem 0; }
.skeleton { background: var(--surface); border-radius: 8px; animation: pulse 1.4s ease-in-out infinite; }
.skeleton--card { width: 100%; height: 72px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
</style>
