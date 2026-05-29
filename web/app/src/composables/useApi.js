import { useAuthStore } from '@/stores/authStore'

/**
 * Composable para llamadas autenticadas a la API REST.
 *
 * Sustituye a `apiFetch()` del legacy (shared.js).
 * Inyecta automáticamente el header Authorization con el JWT vigente
 * (refrescándolo si está próximo a expirar) y maneja el login redirect
 * si la sesión ya no es válida.
 *
 * @example
 * import { useApi } from '@/composables/useApi'
 * const { apiFetch } = useApi()
 * const res = await apiFetch('/sentinel/results?type=nmap')
 * const data = await res.json()
 *
 * @returns {{ apiFetch: (path: string, options?: object) => Promise<Response|null> }}
 */
export function useApi() {
  const auth = useAuthStore()

  /**
   * Wrapper autenticado sobre fetch.
   *
   * - Obtiene el token vía authStore (con refresco automático si procede).
   * - Si el token no está disponible, ejecuta logout() y devuelve null.
   * - Añade cabeceras Authorization y Content-Type por defecto.
   * - Si el body es FormData, elimina Content-Type para que el navegador
   *   ponga el boundary correcto automáticamente.
   *
   * @param {string} path - Ruta de la API (ej: '/sentinel/nmap')
   * @param {object} [options={}] - Opciones de fetch (method, body, headers, etc.)
   * @param {object} [options.headers] - Cabeceras adicionales que se mezclan con las de auth
   * @param {object|FormData|null} [options.body] - Cuerpo de la petición
   * @returns {Promise<Response|null>} Response de fetch, o null si no hay sesión o hay error de red
   */
  async function apiFetch(path, options = {}) {
    const token = await auth.getToken()
    if (!token) {
      auth.logout()
      return null
    }

    const headers = {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(options.headers ?? {}),
    }

    if (options.body instanceof FormData) {
      delete headers['Content-Type']
    }

    try {
      return await fetch(path, { ...options, headers })
    } catch (e) {
      console.error('[SeQ] apiFetch error:', e)
      return null
    }
  }

  return { apiFetch }
}
