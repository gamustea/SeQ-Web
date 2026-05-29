import { defineStore } from 'pinia'
import { reactive, ref } from 'vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

/**
 * Store de perfil de usuario — carga y actualiza los datos personales.
 *
 * Sustituye la lógica de profile.js (122 líneas de manipulación DOM directa).
 * Centraliza las llamadas GET/PUT de /users/me y el cambio de contraseña.
 */
export const useProfileStore = defineStore('profile', () => {
  const { apiFetch } = useApi()
  const toast = useToastStore()

  /** Datos del perfil del usuario autenticado */
  const profile = reactive({ first_name: '', last_name: '', email: '', username: '', created_at: '' })
  /** Indicador de carga en curso */
  const loading = ref(false)

  /**
   * Obtiene el perfil del usuario autenticado desde GET /users/me.
   */
  async function loadProfile() {
    loading.value = true
    try {
      const res = await apiFetch('/users/me')
      if (!res?.ok) return
      const data = await res.json()
      Object.assign(profile, {
        first_name: data.first_name || '',
        last_name: data.last_name || '',
        email: data.email || '',
        username: data.username || '',
        created_at: data.created_at || '',
      })
    } finally { loading.value = false }
  }

  /**
   * Actualiza el nombre y apellido del usuario vía PUT /users/me.
   * @param {string} first_name - Nuevo nombre
   * @param {string} last_name - Nuevo apellido
   * @returns {Promise<boolean>} True si se actualizó correctamente
   */
  async function updateProfile(first_name, last_name) {
    const res = await apiFetch('/users/me', {
      method: 'PUT',
      body: JSON.stringify({ first_name, last_name }),
    })
    if (!res?.ok) {
      const data = await res?.json().catch(() => ({}))
      toast.show(data.message || 'Error al actualizar el perfil.', 'error')
      return false
    }
    toast.show('Perfil actualizado.', 'success')
    await loadProfile()
    return true
  }

  /**
   * Cambia la contraseña del usuario vía PUT /users/change-password.
   * @param {string} newPassword - Nueva contraseña (mín. 8 caracteres)
   * @returns {Promise<boolean>} True si se cambió correctamente
   */
  async function changePassword(newPassword) {
    const res = await apiFetch('/users/change-password', {
      method: 'PUT',
      body: JSON.stringify({ newPassword }),
    })
    if (!res?.ok) {
      const data = await res?.json().catch(() => ({}))
      toast.show(data.message || 'Error al cambiar la contraseña.', 'error')
      return false
    }
    toast.show('Contraseña actualizada. Cerrando sesión…', 'success')
    return true
  }

  return { profile, loading, loadProfile, updateProfile, changePassword }
})
