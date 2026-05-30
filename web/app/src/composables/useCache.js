/**
 * Caché genérico en memoria con TTL, LRU y key prefix.
 *
 * Principios SOLID:
 * - Single Responsibility: solo gestiona entradas de caché.
 * - Open/Closed: el backend de storage se inyecta (abierto a extensi�n, cerrado
 *   a modificar la interfaz p�blica).
 * - Liskov Substitution: cualquier backend que implemente {get,set,delete,has,clear,size}
 *   es intercambiable (Strategy Pattern).
 * - Interface Segregation: API m�nima � get, set, has, delete, clear, size.
 * - Dependency Inversion: depende de la abstracci�n del storage, no de implementaciones concretas.
 *
 * @example
 * import { useCache } from '@/composables/useCache'
 *
 * const docCache = useCache({ keyPrefix: 'aegis:doc:', maxSize: 50 })
 * docCache.set('42', { title: 'Phishing' })
 * const doc = docCache.get('42')  // → { title: 'Phishing' }
 *
 * const formCache = useCache({ ttl: 5 * 60 * 1000 })  // 5 minutos
 * formCache.set('draft', { ... })
 *
 * // Backend personalizado (sessionStorage):
 * const sessionCache = useCache({ storage: sessionStorageAdapter })
 */

/**
 * Backend de almacenamiento en memoria con Map nativo.
 * Cumple la interfaz requerida por useCache.
 */
export function createMapStorage() {
  const _map = new Map()

  return {
    get(key) {
      return _map.get(key)
    },
    set(key, value) {
      _map.set(key, value)
    },
    delete(key) {
      return _map.delete(key)
    },
    has(key) {
      return _map.has(key)
    },
    clear() {
      _map.clear()
    },
    get size() {
      return _map.size
    },
  }
}

/**
 * Caché genérico.
 *
 * @param {object} [options={}]
 * @param {object} [options.storage] - Backend de almacenamiento (por defecto MapStorage en memoria).
 *   Debe implementar: get(key), set(key, value), delete(key), has(key), clear(), size.
 * @param {number} [options.maxSize=Infinity] - N�mero m�ximo de entradas. Al excederlo, se evicta la
 *   entrada menos recientemente usada (LRU).
 * @param {number} [options.ttl=Infinity] - Tiempo de vida en milisegundos.
 *   Las entradas m�s antiguas que este valor se consideran expiradas y se eliminan autom�ticamente.
 * @param {string} [options.keyPrefix=''] - Prefijo autom�tico para todas las claves.
 *   Permite namespacing (ej. 'aegis:doc:') para evitar colisiones entre m�dulos.
 * @returns {{ get, set, has, delete, clear, size }}
 */
export function useCache(options = {}) {
  const {
    storage = createMapStorage(),
    maxSize = Infinity,
    ttl = Infinity,
    keyPrefix = '',
  } = options

  /** Orden de acceso para LRU: el �ltimo elemento es el m�s recientemente usado */
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

  /**
   * Obtiene una entrada de la caché.
   * Si la entrada ha expirado (TTL), se elimina y devuelve undefined.
   * El acceso actualiza la posici�n LRU de la entrada.
   *
   * @param {string|number} key
   * @returns {*|undefined} El valor almacenado, o undefined si no existe o expir�.
   */
  function get(key) {
    const fullKey = _fullKey(key)
    if (!storage.has(fullKey)) return undefined

    const entry = storage.get(fullKey)

    if (_isExpired(entry)) {
      storage.delete(fullKey)
      _removeFromOrder(fullKey)
      return undefined
    }

    _touch(fullKey)
    return entry.value
  }

  /**
   * Almacena un valor en la caché.
   * Si se excede maxSize, se evicta la entrada menos recientemente usada (LRU).
   *
   * @param {string|number} key
   * @param {*} value
   */
  function set(key, value) {
    const fullKey = _fullKey(key)
    _removeFromOrder(fullKey)
    _accessOrder.push(fullKey)
    storage.set(fullKey, { value, _ts: Date.now() })
    _evict()
  }

  /**
   * Comprueba si una clave existe en la caché (y no ha expirado).
   *
   * @param {string|number} key
   * @returns {boolean}
   */
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

  /**
   * Elimina una entrada de la caché.
   *
   * @param {string|number} key
   * @returns {boolean} true si la entrada exist�a y fue eliminada.
   */
  function _delete(key) {
    const fullKey = _fullKey(key)
    _removeFromOrder(fullKey)
    return storage.delete(fullKey)
  }

  /** Elimina todas las entradas de la caché. */
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
    get size() {
      return storage.size
    },
  }
}
