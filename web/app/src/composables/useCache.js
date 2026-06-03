/**
 * Caché genérico con backends intercambiables (Strategy Pattern).
 *
 * Backends nativos:
 * - `'memory'` (default) — Map en RAM, volátil.
 * - `'session'` — sessionStorage, persiste en la pestaña.
 * - `'local'`  — localStorage, persiste entre sesiones.
 * - También acepta un objeto adaptador personalizado.
 *
 * @example
 * import { useCache } from '@/composables/useCache'
 *
 * const docCache = useCache({ keyPrefix: 'aegis:doc:', maxSize: 50 })
 * docCache.set('42', { title: 'Phishing' })
 * const doc = docCache.get('42')
 *
 * const sessionCache = useCache({ storage: 'session', ttl: 5 * 60 * 1000 })
 * sessionCache.set('profile', { name: 'Ada' })
 *
 * const customCache = useCache({ storage: myAdapter, maxSize: 100 })
 */

/**
 * Backend de almacenamiento en memoria con Map nativo.
 */
export function createMapStorage() {
  const _map = new Map()

  return {
    get(key) { return _map.get(key) },
    set(key, value) { _map.set(key, value) },
    delete(key) { return _map.delete(key) },
    has(key) { return _map.has(key) },
    clear() { _map.clear() },
    get size() { return _map.size },
  }
}

/**
 * Backend de almacenamiento persistente sobre Web Storage.
 *
 * @param {'session'|'local'} type - Tipo de Web Storage
 * @param {string} keyPrefix - Namespace para auto-hidratar el tracking al crearse
 */
function createWebStorage(type, keyPrefix = '') {
  const store = type === 'local' ? localStorage : sessionStorage
  const _keys = new Set()

  for (let i = 0; i < store.length; i++) {
    const k = store.key(i)
    if (k && (!keyPrefix || k.startsWith(keyPrefix))) _keys.add(k)
  }

  function _read(key) {
    try {
      const raw = store.getItem(key)
      return raw ? JSON.parse(raw) : undefined
    } catch { return undefined }
  }

  return {
    get(key) { return _read(key) },
    set(key, value) {
      _keys.add(key)
      try { store.setItem(key, JSON.stringify(value)) } catch {}
    },
    delete(key) {
      _keys.delete(key)
      store.removeItem(key)
    },
    has(key) { return store.getItem(key) !== null },
    clear() {
      for (const k of _keys) store.removeItem(k)
      _keys.clear()
    },
    get size() { return _keys.size },
  }
}

export function createSessionStorage(keyPrefix) {
  return createWebStorage('session', keyPrefix)
}

export function createLocalStorage(keyPrefix) {
  return createWebStorage('local', keyPrefix)
}

function resolveStorage(storageOption, keyPrefix) {
  if (!storageOption || storageOption === 'memory') return createMapStorage()
  if (storageOption === 'session') return createSessionStorage(keyPrefix)
  if (storageOption === 'local') return createLocalStorage(keyPrefix)
  return storageOption
}

/**
 * Caché genérico con TTL, LRU y backends intercambiables.
 *
 * @param {object} [options={}]
 * @param {string|object} [options.storage] - Backend: 'memory'|'session'|'local' o adaptador.
 * @param {number} [options.maxSize=Infinity] - Límite LRU de entradas.
 * @param {number} [options.ttl=Infinity] - TTL en milisegundos.
 * @param {string} [options.keyPrefix=''] - Namespace para claves.
 * @returns {{ get, set, has, delete, clear, size }}
 */
export function useCache(options = {}) {
  const {
    storage: storageOption,
    maxSize = Infinity,
    ttl = Infinity,
    keyPrefix = '',
  } = options

  const storage = resolveStorage(storageOption, keyPrefix)
  const _accessOrder = []

  function _fullKey(key) {
    return keyPrefix + String(key)
  }

  function _touch(fullKey) {
    _removeFromOrder(fullKey)
    _accessOrder.push(fullKey)
  }

  function _removeFromOrder(fullKey) {
    const idx = _accessOrder.indexOf(fullKey)
    if (idx > -1) _accessOrder.splice(idx, 1)
  }

  function _evict() {
    while (_accessOrder.length > 0 && storage.size > maxSize) {
      const oldest = _accessOrder.shift()
      storage.delete(oldest)
    }
  }

  function _isExpired(entry) {
    return ttl !== Infinity && Date.now() - entry._ts > ttl
  }

  function get(key) {
    const fullKey = _fullKey(key)
    if (!storage.has(fullKey)) return undefined
    const entry = storage.get(fullKey)
    if (!entry || typeof entry !== 'object' || typeof entry._ts !== 'number') {
      storage.delete(fullKey)
      _removeFromOrder(fullKey)
      return undefined
    }
    if (_isExpired(entry)) {
      storage.delete(fullKey)
      _removeFromOrder(fullKey)
      return undefined
    }
    _touch(fullKey)
    return entry.value
  }

  function set(key, value) {
    const fullKey = _fullKey(key)
    _removeFromOrder(fullKey)
    _accessOrder.push(fullKey)
    storage.set(fullKey, { value, _ts: Date.now() })
    _evict()
  }

  function has(key) {
    const fullKey = _fullKey(key)
    if (!storage.has(fullKey)) return false
    const entry = storage.get(fullKey)
    if (_isExpired(entry)) {
      storage.delete(fullKey)
      _removeFromOrder(fullKey)
      return false
    }
    return true
  }

  function _delete(key) {
    const fullKey = _fullKey(key)
    _removeFromOrder(fullKey)
    return storage.delete(fullKey)
  }

  function clear() {
    _accessOrder.length = 0
    storage.clear()
  }

  return {
    get,
    set,
    has,
    delete: _delete,
    clear,
    get size() { return storage.size },
  }
}
