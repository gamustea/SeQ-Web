import { defineStore } from 'pinia'
import { reactive, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

/**
 * Store de configuración del sistema — carga/guarda SecOpsConfig.json.
 *
 * Sustituye la lógica de config.js (147 líneas). El JSON anidado del backend
 * se aplana a claves con notación de punto para poder usar v-model directamente
 * en los inputs del formulario. Al guardar se reconstruye el objeto anidado y
 * se envía completo a PUT /system.
 */
export const useConfigStore = defineStore('config', () => {
  const { apiFetch } = useApi()
  const toast = useToastStore()

  /** Configuración aplanada con claves "section.sub.key" (reactivo para v-model) */
  const configFlat = reactive({})
  /** Copia de la configuración original para el botón de reset */
  let originalFlat = {}
  /** Carga inicial en curso */
  const loading = ref(false)
  /** Guardado en curso */
  const saving = ref(false)

  /** Aplana un objeto anidado a claves con notación de punto */
  function _flatten(obj, prefix = '') {
    const result = {}
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k
      if (v && typeof v === 'object' && !Array.isArray(v)) {
        Object.assign(result, _flatten(v, key))
      } else {
        result[key] = v ?? ''
      }
    }
    return result
  }

  /** Des-aplana claves con punto de vuelta a objeto anidado */
  function _unflatten(flat) {
    const result = {}
    for (const [key, val] of Object.entries(flat)) {
      const parts = key.split('.')
      let current = result
      for (let i = 0; i < parts.length - 1; i++) {
        if (!current[parts[i]] || typeof current[parts[i]] !== 'object') {
          current[parts[i]] = {}
        }
        current = current[parts[i]]
      }
      current[parts[parts.length - 1]] = val
    }
    return result
  }

  /** Fusión profunda: clona target y sobrescribe con source */
  function _deepMerge(target, source) {
    const result = JSON.parse(JSON.stringify(target))
    for (const [k, v] of Object.entries(source)) {
      if (v && typeof v === 'object' && !Array.isArray(v) && result[k] && typeof result[k] === 'object' && !Array.isArray(result[k])) {
        result[k] = _deepMerge(result[k], v)
      } else {
        result[k] = v
      }
    }
    return result
  }

  /**
   * Carga la configuración desde GET /system y la aplana.
   */
  async function loadConfig() {
    loading.value = true
    try {
      const res = await apiFetch('/system')
      if (!res?.ok) { toast.show('Error al cargar la configuración.', 'error'); return }
      const data = await res.json()
      const flat = _flatten(data)
      Object.assign(configFlat, flat)
      originalFlat = { ...flat }
    } finally { loading.value = false }
  }

  /** Restaura los valores del formulario a la última configuración guardada */
  function resetForm() {
    Object.assign(configFlat, originalFlat)
  }

  /**
   * Guarda la configuración actual vía PUT /system.
   * @returns {Promise<boolean>} True si se guardó correctamente
   */
  async function saveConfig() {
    saving.value = true
    try {
      const merged = _deepMerge(_unflatten(originalFlat), _unflatten({ ...configFlat }))
      const res = await apiFetch('/system', {
        method: 'PUT',
        body: JSON.stringify(merged),
      })
      if (!res?.ok) {
        const data = await res?.json().catch(() => ({}))
        toast.show(data.message || 'Error al guardar la configuración.', 'error')
        return false
      }
      originalFlat = { ...configFlat }
      toast.show('Configuración guardada.', 'success')
      return true
    } finally { saving.value = false }
  }

  return { configFlat, loading, saving, loadConfig, resetForm, saveConfig }
})
