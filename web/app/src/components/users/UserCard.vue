<template>
  <div class="user-card" :class="`user-card--${roleClass}`" @click="$emit('details', user.id)">
    <div class="card-avatar">{{ initials }}</div>
    <div class="card-body">
      <div class="card-name">{{ user.first_name || '—' }} {{ user.last_name || '' }}</div>
      <div class="card-username">@{{ user.username }}</div>
      <div class="card-meta">
        <span class="card-email" :title="user.email">{{ user.email }}</span>
        <span class="card-id">#{{ user.id }}</span>
      </div>
      <div class="card-footer">
        <span class="card-role-badge" :class="`role-badge--${roleClass}`">{{ roleLabel }}</span>
        <span v-if="user.created_at" class="card-date">{{ formatDate(user.created_at) }}</span>
      </div>
    </div>
    <div class="card-chevron">&rsaquo;</div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useUtils } from '@/composables/useUtils'

const { formatDate, getInitials } = useUtils()

const props = defineProps({
  user: { type: Object, required: true },
})

defineEmits(['details'])

const initials = computed(() => getInitials(props.user.first_name, props.user.last_name))

const roleClass = computed(() => {
  const r = props.user.role || 'role_user'
  if (r === 'role_root') return 'root'
  if (r === 'role_admin') return 'admin'
  return 'user'
})

const roleLabel = computed(() => {
  const r = props.user.role || 'role_user'
  if (r === 'role_root') return 'Root'
  if (r === 'role_admin') return 'Admin'
  return 'Usuario'
})
</script>

<style scoped>
.user-card {
  display: flex; align-items: center; gap: 1rem; padding: 1rem;
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  cursor: pointer; transition: border-color 0.2s, transform 0.15s;
}
.user-card:hover { transform: translateY(-1px); }
.user-card--root  { border-color: rgba(239,68,68,0.25); }
.user-card--admin { border-color: rgba(251,191,36,0.2); }
.user-card--user  { border-color: rgba(96,165,250,0.15); }

.card-avatar {
  width: 48px; height: 48px; border-radius: 50%; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 1.1rem; font-weight: 700; font-family: var(--font-mono);
  background: var(--accent); color: var(--bg);
}
.user-card--root  .card-avatar { background: var(--danger); }
.user-card--admin .card-avatar { background: var(--warn); color: var(--bg); }
.user-card--user  .card-avatar { background: var(--info); }

.card-body { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 0.2rem; }
.card-name { font-size: 1rem; font-weight: 700; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.card-username { font-size: 0.82rem; color: var(--text-dim); }
.card-meta { display: flex; gap: 0.75rem; font-size: 0.78rem; color: var(--text-muted); }
.card-email { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 160px; }
.card-id { font-family: var(--font-mono); opacity: 0.7; }
.card-footer { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.25rem; }
.card-role-badge {
  font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em;
  padding: 0.15rem 0.5rem; border-radius: 4px;
}
.role-badge--root  { background: rgba(239,68,68,0.15);  color: var(--danger); }
.role-badge--admin { background: rgba(251,191,36,0.15); color: var(--warn); }
.role-badge--user  { background: rgba(96,165,250,0.12); color: var(--info); }
.card-date { font-size: 0.7rem; color: var(--text-muted); margin-left: auto; }

.card-chevron { font-size: 1.4rem; color: var(--text-muted); flex-shrink: 0; }
</style>
