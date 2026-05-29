<template>
  <span class="badge" :class="'badge--' + classMap">{{ label }}</span>
</template>

<script setup>
/**
 * StatusBadge — Pastilla de estado genérica.
 * Mapea los estados internos a etiquetas CSS del sistema de diseño.
 *
 * @vue-prop {'running'|'done'|'finished'|'pending'|'error'|'cancelled'} status
 */
import { computed } from 'vue'

const props = defineProps({ status: { type: String, required: true } })

const MAP = {
  running: ['running', 'Ejecutando'],
  done: ['done', 'Completado'],
  finished: ['done', 'Completado'],
  pending: ['pending', 'Pendiente'],
  error: ['error', 'Error'],
  cancelled: ['cancelled', 'Cancelado'],
}

const classMap = computed(() => (MAP[(props.status ?? '').toLowerCase()] ?? ['pending'])[0])
const label = computed(() => (MAP[(props.status ?? '').toLowerCase()] ?? ['pending', props.status ?? '—'])[1])
</script>
