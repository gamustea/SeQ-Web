import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

/**
 * Clave usada en sessionStorage para persistir los datos de sesión.
 * @type {string}
 */
const STORAGE_KEY = 'seq_session'

/**
 * Store de autenticación — gestiona JWT, login, logout y refresh automático.
 *
 * Sustituye al `SeqSession` del legacy (shared.js). Usa Pinia para que los cambios
 * de estado (login, logout, rol) sean reactivos y cualquier componente se entere.
 *
 * @example
 * import { useAuthStore } from '@/stores/authStore'
 * const auth = useAuthStore()
 * auth.login('root', 'admin')  // POST /oauth/token, guarda en sessionStorage
 * auth.isAdmin                 // true si el rol es admin o root
 * auth.username()              // extraído del payload JWT
 */
export const useAuthStore = defineStore('auth', () => {
  /** @type {import('vue').Ref<string|null>} Token JWT de acceso */
  const accessToken = ref(null)
  /** @type {import('vue').Ref<string|null>} Token de refresco */
  const refreshToken = ref(null)
  /** @type {import('vue').Ref<number>} Timestamp UNIX de expiración del access token */
  const expiresAt = ref(0)
  /** @type {import('vue').Ref<string>} Rol del usuario (role_user, role_admin, role_root) */
  const role = ref('role_user')

  /** @type {import('vue').ComputedRef<boolean>} True si hay un access token vigente */
  const isAuthenticated = computed(() => !!accessToken.value)
  /** @type {import('vue').ComputedRef<boolean>} True si es admin o root */
  const isAdmin = computed(() => role.value === 'role_admin' || role.value === 'role_root')
  /** @type {import('vue').ComputedRef<boolean>} True si es root */
  const isRoot = computed(() => role.value === 'role_root')

  /**
   * Decodifica el payload de un JWT sin verificar la firma.
   * Extrae username, role y demás claims del cuerpo (parte central).
   * @param {string} token - JWT en formato header.payload.signature
   * @returns {object} Payload decodificado, o {} si falla el parseo
   */
  function parseJwt(token) {
    try {
      return JSON.parse(atob(token.split('.')[1]))
    } catch {
      return {}
    }
  }

  /**
   * Devuelve el nombre de usuario extraído del JWT en memoria.
   * No requiere llamada a la API. Vacío si no hay sesión.
   * @returns {string}
   */
  function username() {
    if (!accessToken.value) return ''
    const payload = parseJwt(accessToken.value)
    return payload.username || payload.sub || ''
  }

  /**
   * Restaura la sesión desde sessionStorage.
   * Se llama en App.vue al montar la aplicación.
   * @returns {boolean} True si se encontró una sesión válida
   */
  function loadFromStorage() {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (!raw) return false
    try {
      const data = JSON.parse(raw)
      if (!data?.accessToken) return false
      accessToken.value = data.accessToken
      refreshToken.value = data.refreshToken
      expiresAt.value = data.expiresAt
      role.value = data.role || 'role_user'
      return true
    } catch {
      return false
    }
  }

  /**
   * Persiste el estado actual de la sesión en sessionStorage.
   * Se llama automáticamente tras login() y refreshAccessToken().
   */
  function saveToStorage() {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
      accessToken: accessToken.value,
      refreshToken: refreshToken.value,
      expiresAt: expiresAt.value,
      role: role.value,
    }))
  }

  /**
   * Autentica al usuario contra /oauth/token con grant_type password.
   * En caso de éxito, persiste los tokens en sessionStorage y actualiza
   * el estado reactivo del store.
   * @param {string} username - Nombre de usuario
   * @param {string} password - Contraseña
   * @throws {Error} Si las credenciales son inválidas, hay rate-limit, o el servidor devuelve error
   * @example
   * try { await auth.login('root', 'admin') } catch (e) { console.error(e.message) }
   */
  async function login(username, password) {
    const res = await fetch('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grantType: 'password', username, password }),
    })
    const data = await res.json()
    if (!res.ok) {
      if (res.status === 401) throw new Error('Credenciales incorrectas.')
      if (res.status === 429) throw new Error('Demasiados intentos. Espera unos minutos.')
      throw new Error(data.error_description || `Error del servidor (${res.status})`)
    }
    accessToken.value = data.access_token
    refreshToken.value = data.refresh_token
    expiresAt.value = Date.now() + data.expires_in * 1000
    role.value = data.role || 'role_user'
    saveToStorage()
  }

  /**
   * Obtiene el access token vigente, refrescándolo si está a punto de expirar
   * (menos de 60 segundos restantes). Si el refresco falla o no hay sesión,
   * redirige al login.
   * @returns {Promise<string|null>} Access token, o null si la sesión terminó
   */
  async function getToken() {
    if (!accessToken.value) return null
    if (Date.now() > expiresAt.value - 60000) {
      const ok = await refreshAccessToken()
      if (!ok) return null
    }
    return accessToken.value
  }

  /**
   * Renueva el access token mediante /oauth/token con grant_type refresh_token.
   * Actualiza y persiste el nuevo token automáticamente.
   * @returns {Promise<boolean>} True si el refresco fue exitoso
   */
  async function refreshAccessToken() {
    if (!refreshToken.value) return false
    try {
      const res = await fetch('/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grantType: 'refresh_token', refresh_token: refreshToken.value }),
      })
      if (!res.ok) return false
      const data = await res.json()
      accessToken.value = data.access_token
      expiresAt.value = Date.now() + data.expires_in * 1000
      saveToStorage()
      return true
    } catch {
      return false
    }
  }

  /**
   * Cierra la sesión: revoca el token en el servidor (fire-and-forget),
   * limpia el estado y el sessionStorage, y redirige al login.
   */
  function logout() {
    const token = accessToken.value
    accessToken.value = null
    refreshToken.value = null
    expiresAt.value = 0
    role.value = 'role_user'
    sessionStorage.removeItem(STORAGE_KEY)
    if (token) {
      fetch('/oauth/revoke', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      }).catch(() => {})
    }
    window.location.href = '/login'
  }

  return {
    accessToken, refreshToken, expiresAt, role,
    isAuthenticated, isAdmin, isRoot,
    username, loadFromStorage, saveToStorage,
    login, getToken, logout,
  }
})
