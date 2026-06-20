import { ref, computed } from 'vue'

/**
 * Gestiona la seleccion multiple de filas para operaciones batch.
 *
 * Responsabilidad unica: estado de seleccion, sin acoplarse a
 * ninguna operacion batch concreta (add-to-folder, delete, etc.).
 */
export function useBatchSelection() {
  const selectedIds = ref(new Set())

  const selectedCount = computed(() => selectedIds.value.size)
  const selectedArray = computed(() => [...selectedIds.value])

  function toggle(id) {
    const s = new Set(selectedIds.value)
    if (s.has(id)) s.delete(id)
    else s.add(id)
    selectedIds.value = s
  }

  function selectAll(ids) {
    const s = new Set(selectedIds.value)
    const allSelected = ids.every(id => s.has(id))
    if (allSelected) ids.forEach(id => s.delete(id))
    else ids.forEach(id => s.add(id))
    selectedIds.value = s
  }

  function clear() {
    selectedIds.value = new Set()
  }

  return {
    selectedIds,
    selectedCount,
    selectedArray,
    toggle,
    selectAll,
    clear,
  }
}
