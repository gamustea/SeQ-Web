<template>
  <div v-if="totalPages > 1" class="pagination">
    <button class="page-btn" :disabled="current <= 1" @click="$emit('go', current - 1)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
    </button>

    <button
      v-for="page in visiblePages"
      :key="page"
      class="page-btn"
      :class="{ active: page === current }"
      @click="$emit('go', page)"
    >{{ page }}</button>

    <button class="page-btn" :disabled="current >= totalPages" @click="$emit('go', current + 1)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
    </button>

    <span class="page-info">{{ current }} / {{ totalPages }}</span>
  </div>
</template>

<script setup>
/**
 * AppPagination — Control de paginación reutilizable.
 *
 * @vue-prop {number} current - Página activa actual
 * @vue-prop {number} total - Número total de elementos
 * @vue-prop {number} [perPage=10] - Elementos por página
 *
 * @vue-emit {number} go - Emite el número de página destino
 */
import { computed } from 'vue'

const props = defineProps({
  current: { type: Number, required: true },
  total: { type: Number, required: true },
  perPage: { type: Number, default: 10 },
})

defineEmits(['go'])

const totalPages = computed(() => Math.ceil(props.total / props.perPage) || 1)

const visiblePages = computed(() => {
  const max = 5
  let start = Math.max(1, props.current - Math.floor(max / 2))
  let end = Math.min(totalPages.value, start + max - 1)
  if (end - start < max - 1) start = Math.max(1, end - max + 1)
  const pages = []
  for (let i = start; i <= end; i++) pages.push(i)
  return pages
})
</script>

<style scoped>
.pagination { display: flex; align-items: center; gap: 0.35rem; padding: 1rem 0; justify-content: center; }
.page-btn {
  min-width: 32px; height: 32px; display: flex; align-items: center; justify-content: center;
  background: var(--surface-2); border: 1px solid var(--border); border-radius: 7px;
  color: var(--text-dim); font-size: 0.82rem; font-weight: 500; cursor: pointer;
  transition: all 0.2s ease; font-family: var(--font-mono);
}
.page-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.page-btn.active { background: var(--accent-dim); border-color: var(--accent); color: var(--accent); font-weight: 600; }
.page-btn:disabled { opacity: 0.25; cursor: not-allowed; }
.page-btn svg { width: 14px; height: 14px; }
.page-info { font-size: 0.75rem; color: var(--text-muted); margin-left: 0.5rem; font-family: var(--font-mono); }
</style>
