<template>
  <Teleport to="body">
    <div v-if="show" class="modal-overlay" @click.self="$emit('close')">
      <div class="modal modal--lg">
        <div class="modal-header">
          <h3>Detalles del Usuario</h3>
          <button class="modal-close" @click="$emit('close')">&times;</button>
        </div>

        <div v-if="loadingUser" class="modal-loading">Cargando…</div>

        <template v-else-if="user">
          <!-- Profile -->
          <div class="detail-header">
            <div class="detail-avatar" :class="`role-avatar--${roleClass}`">{{ initials }}</div>
            <div class="detail-names">
              <h4>{{ user.first_name || '—' }} {{ user.last_name || '' }}</h4>
              <p>@{{ user.username }}</p>
            </div>
            <span class="detail-role-badge" :class="`role-badge--${roleClass}`">{{ roleLabel }}</span>
          </div>

          <div class="detail-grid">
            <div class="detail-item">
              <span class="detail-label">Nombre</span>
              <span class="detail-value">{{ user.first_name || '—' }} {{ user.last_name || '' }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Email</span>
              <span class="detail-value">{{ user.email }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Rol</span>
              <span class="detail-value">{{ roleLabel }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Creado</span>
              <span class="detail-value">{{ formatDate(user.created_at) }}</span>
            </div>
          </div>

          <!-- Attributes -->
          <div class="detail-section">
            <h4>Atributos ABAC</h4>

            <div class="attr-tags">
              <span v-for="attr in attributes" :key="attr" class="attr-tag">
                {{ attr }}
                <button v-if="canManage" class="attr-remove" @click="handleRemoveAttribute(attr)" title="Eliminar">&times;</button>
              </span>
              <span v-if="attributes.length === 0" class="attr-empty">Sin atributos</span>
            </div>

            <!-- Add attribute form -->
            <div v-if="canManage" class="attr-manage">
              <button v-if="!showAttrForm" class="btn btn--sm btn--secondary" @click="showAttrForm = true">+ Añadir atributo</button>

              <div v-else class="attr-form">
                <div v-for="mod in ALL_ATTRIBUTES" :key="mod.module" class="attr-module">
                  <h5>{{ mod.module }}</h5>
                  <div class="attr-checks">
                    <label v-for="a in mod.attrs" :key="a.name" class="attr-check">
                      <input type="checkbox" :value="a.name" v-model="selectedAttrs" :disabled="attributes.includes(a.name)" />
                      <span>{{ a.desc }}</span>
                    </label>
                  </div>
                </div>

                <div class="attr-form-actions">
                  <button type="button" class="btn btn--sm btn--secondary" @click="showAttrForm = false; selectedAttrs = []">Cancelar</button>
                  <button type="button" class="btn btn--sm btn--primary" :disabled="selectedAttrs.length === 0" @click="handleAddAttributes">Guardar</button>
                </div>
              </div>
            </div>
          </div>
        </template>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useUtils } from '@/composables/useUtils'
import { useAuthStore } from '@/stores/authStore'
import { useUsersStore } from '@/stores/usersStore'

const { formatDate, getInitials } = useUtils()
const auth = useAuthStore()
const store = useUsersStore()

const props = defineProps({ show: { type: Boolean, default: false }, userId: { type: [Number, String], default: null } })
const emit = defineEmits(['close', 'refresh'])

const user = ref(null)
const attributes = ref([])
const loadingUser = ref(false)
const showAttrForm = ref(false)
const selectedAttrs = ref([])

const canManage = computed(() => auth.isAdmin)

const ALL_ATTRIBUTES = [
  {
    module: 'Aegis',
    attrs: [
      { name: 'aegis_read', desc: 'Lectura' },
      { name: 'aegis_write', desc: 'Escritura' },
      { name: 'aegis_create', desc: 'Creación' },
      { name: 'aegis_delete', desc: 'Eliminación' },
    ],
  },
  {
    module: 'Sentinel',
    attrs: [
      { name: 'sentinel_read', desc: 'Lectura' },
      { name: 'sentinel_write', desc: 'Escritura' },
      { name: 'sentinel_create', desc: 'Creación' },
      { name: 'sentinel_delete', desc: 'Eliminación' },
    ],
  },
  {
    module: 'Acheron',
    attrs: [
      { name: 'acheron_read', desc: 'Lectura' },
      { name: 'acheron_write', desc: 'Escritura' },
      { name: 'acheron_create', desc: 'Creación' },
      { name: 'acheron_delete', desc: 'Eliminación' },
    ],
  },
]

const initials = computed(() => getInitials(user.value?.first_name || '', user.value?.last_name || ''))

const roleClass = computed(() => {
  const r = user.value?.role || 'role_user'
  if (r === 'role_root') return 'root'
  if (r === 'role_admin') return 'admin'
  return 'user'
})

const roleLabel = computed(() => {
  const r = user.value?.role || 'role_user'
  if (r === 'role_root') return 'Root'
  if (r === 'role_admin') return 'Admin'
  return 'Usuario'
})

watch(() => props.show, async (v) => {
  if (!v || !props.userId) return
  loadingUser.value = true
  showAttrForm.value = false
  selectedAttrs.value = []
  try {
    const found = store.users.find(u => u.id == props.userId) || null
    user.value = found
    attributes.value = await store.loadUserAttributes(props.userId)
  } finally { loadingUser.value = false }
})

async function handleRemoveAttribute(attr) {
  const ok = await store.removeAttributes(props.userId, [attr])
  if (ok) attributes.value = await store.loadUserAttributes(props.userId)
}

async function handleAddAttributes() {
  if (selectedAttrs.value.length === 0) return
  const ok = await store.addAttributes(props.userId, selectedAttrs.value)
  if (ok) {
    showAttrForm.value = false
    selectedAttrs.value = []
    attributes.value = await store.loadUserAttributes(props.userId)
  }
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; z-index: 100; background: rgba(0,0,0,.65); display: flex; align-items: center; justify-content: center; padding: 1.5rem; }
.modal { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; width: 100%; max-width: 560px; max-height: 90vh; overflow-y: auto; padding: 1.75rem; }
.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem; }
.modal-header h3 { font-size: 1.15rem; font-weight: 700; color: var(--text); margin: 0; }
.modal-close { background: none; border: none; font-size: 1.5rem; color: var(--text-muted); cursor: pointer; padding: 0 0.25rem; line-height: 1; }
.modal-close:hover { color: var(--text); }
.modal-loading { text-align: center; padding: 3rem 0; color: var(--text-muted); font-size: 0.9rem; }

.detail-header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1.25rem; }
.detail-avatar {
  width: 56px; height: 56px; border-radius: 50%; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 1.25rem; font-weight: 700; font-family: var(--font-mono);
  background: var(--accent); color: var(--bg);
}
.role-avatar--root  { background: var(--danger); }
.role-avatar--admin { background: var(--warn); color: var(--bg); }
.role-avatar--user  { background: var(--info); }

.detail-names { flex: 1; min-width: 0; }
.detail-names h4 { font-size: 1.15rem; font-weight: 700; color: var(--text); margin: 0 0 0.15rem; }
.detail-names p { font-size: 0.82rem; color: var(--text-dim); margin: 0; }

.detail-role-badge { font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; padding: 0.15rem 0.55rem; border-radius: 4px; }
.role-badge--root  { background: rgba(239,68,68,0.15);  color: var(--danger); }
.role-badge--admin { background: rgba(251,191,36,0.15); color: var(--warn); }
.role-badge--user  { background: rgba(96,165,250,0.12); color: var(--info); }

.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 1.5rem; padding: 1rem; background: var(--bg); border-radius: 8px; }
.detail-item { display: flex; flex-direction: column; gap: 0.15rem; }
.detail-label { font-size: 0.72rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; }
.detail-value { font-size: 0.88rem; color: var(--text); word-break: break-word; }

.detail-section { margin-top: 1.5rem; }
.detail-section h4 { font-size: 0.95rem; font-weight: 600; color: var(--text); margin: 0 0 0.75rem; }

.attr-tags { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.75rem; }
.attr-tag {
  display: inline-flex; align-items: center; gap: 0.35rem;
  padding: 0.25rem 0.55rem; font-size: 0.75rem; font-weight: 500;
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  color: var(--text); font-family: var(--font-mono);
}
.attr-remove { background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 1rem; line-height: 1; padding: 0; display: flex; }
.attr-remove:hover { color: var(--danger); }
.attr-empty { font-size: 0.82rem; color: var(--text-muted); }

.attr-manage { margin-top: 0.75rem; }
.attr-form { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-top: 0.5rem; }
.attr-module { margin-bottom: 0.75rem; }
.attr-module h5 { font-size: 0.8rem; font-weight: 700; color: var(--accent); margin: 0 0 0.35rem; }
.attr-checks { display: flex; flex-wrap: wrap; gap: 0.4rem; }
.attr-check { display: flex; align-items: center; gap: 0.3rem; font-size: 0.78rem; color: var(--text); cursor: pointer; }
.attr-check input { accent-color: var(--accent); cursor: pointer; }
.attr-form-actions { display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 0.75rem; }

.btn {
  padding: 0.5rem 1.25rem; border-radius: 7px; font-size: 0.85rem; font-weight: 600;
  border: 1px solid transparent; cursor: pointer; transition: background 0.2s;
}
.btn--sm { padding: 0.35rem 0.85rem; font-size: 0.78rem; }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn--primary { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.btn--primary:hover:not(:disabled) { filter: brightness(1.15); }
.btn--secondary { background: transparent; color: var(--text-dim); border-color: var(--border); }
.btn--secondary:hover { background: var(--border); color: var(--text); }
</style>
