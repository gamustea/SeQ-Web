<script setup>
/**
 * AppToast — Componente de notificación global.
 *
 * Se renderiza en App.vue mediante Teleport (al final del body).
 * Lee el estado del toastStore y se muestra/oculta reactivamente.
 * Los estilos visuales dependen de la propiedad `type`:
 * success (verde), error (rojo), warn (amarillo), info (azul).
 *
 * @example
 * // En cualquier componente:
 * const toast = useToastStore()
 * toast.show('Operación completada', 'success')
 */
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
.toast { position: fixed; bottom: 2rem; right: 2rem; padding: .75rem 1.25rem; border-radius: 10px; font-size: .88rem; background: var(--surface-2); border: 1px solid var(--border); color: var(--text); z-index: 9999; max-width: 380px; transition: opacity .3s, transform .3s; backdrop-filter: blur(8px); }
.toast--success { border-color: var(--success); }
.toast--error { border-color: var(--danger); }
.toast--warn { border-color: var(--warn); }
.toast--info { border-color: var(--info); }
</style>
