<script setup>
import { useToastStore } from '@/stores/toastStore'
const toast = useToastStore()
</script>

<template>
  <Teleport to="body">
    <div v-if="toast.visible" class="toast visible" :class="toast.type ? `toast--${toast.type}` : ''"
         role="alert" aria-live="assertive">
      {{ toast.message }}
    </div>
  </Teleport>
</template>

<style scoped>
.toast {
  position: fixed; bottom: 2rem; right: 2rem;
  padding: 0.7rem 1.1rem; border-radius: 8px;
  font-size: 0.82rem; font-weight: 500;
  background: var(--surface-3); border: 1px solid var(--border);
  color: var(--text); z-index: 9999; max-width: 380px;
  transition: opacity 0.3s, transform 0.3s;
  backdrop-filter: blur(12px);
  box-shadow: 0 8px 24px rgba(0,0,0,0.3);
}
.toast--success { border-color: var(--success); }
.toast--error { border-color: var(--danger); }
.toast--warn { border-color: var(--warn); }
.toast--info { border-color: var(--info); }
</style>
