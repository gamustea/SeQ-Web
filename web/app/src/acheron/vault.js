/**
 * Modelo de vault del cliente web de Acheron.
 *
 * Espejo en JavaScript de `VaultFactory.fromJson` + `Vault` de AcheronCore:
 * abre un vault cifrado (tal y como lo devuelve `GET /vault`), valida el
 * master password mediante el checker, desenvuelve la vaultKey y permite
 * descifrar/recifrar storables campo a campo.
 *
 * Toda la criptografía corre en el navegador. El master password solo vive en
 * memoria durante la sesión y nunca se envía al servidor.
 */

import {
  deriveKey,
  importVaultKey,
  validateChecker,
  aesGcmEncrypt,
  aesGcmDecrypt,
  sha256Hex,
} from './crypto.js'
import { STORABLE_FIELDS, STORABLE_CATEGORIES, KIND_BY_CATEGORY } from './storableFields.js'

/** Se lanza cuando el master password no valida contra el checker del vault. */
export class WrongPasswordError extends Error {
  constructor(message = 'Wrong master password') {
    super(message)
    this.name = 'WrongPasswordError'
  }
}

/**
 * Abre un vault cifrado y devuelve un manejador con la vaultKey desbloqueada.
 *
 * @param {object} vaultJson  cuerpo de `GET /vault`
 * @param {string} masterPassword
 * @param {string} username  validator del checker (username del usuario)
 * @returns {Promise<OpenVault>}
 * @throws {WrongPasswordError} si el master password es incorrecto
 */
export async function openVault(vaultJson, masterPassword, username) {
  const derivedKey = await deriveKey(masterPassword, vaultJson.algorithm)

  if (!(await validateChecker(derivedKey, vaultJson.checker, username))) {
    throw new WrongPasswordError()
  }

  const vaultKey = await importVaultKey(derivedKey, vaultJson.vaultKey)
  return new OpenVault(vaultJson, vaultKey)
}

/**
 * Vault abierto: conserva la vaultKey en memoria y opera sobre los storables.
 */
export class OpenVault {
  constructor(vaultJson, vaultKey) {
    this.raw = vaultJson
    this.vaultKey = vaultKey
  }

  /**
   * Descifra un storable: devuelve una copia con `title` y los campos
   * sensibles de su categoría en texto plano. Los metadatos se conservan.
   *
   * @param {string} category  p.ej. "accounts"
   * @param {object} item      storable cifrado del vault JSON
   * @returns {Promise<object>}
   */
  async decryptStorable(category, item) {
    return transformStorable(this.vaultKey, category, item, aesGcmDecrypt)
  }

  /**
   * Cifra un storable en texto plano hacia el formato persistible.
   *
   * @param {string} category
   * @param {object} item  storable en claro
   * @returns {Promise<object>}
   */
  async encryptStorable(category, item) {
    return transformStorable(this.vaultKey, category, item, aesGcmEncrypt)
  }

  /**
   * Descifra todos los storables del vault, agrupados por categoría.
   * @returns {Promise<Record<string, object[]>>}
   */
  async decryptAll() {
    const out = {}
    for (const category of STORABLE_CATEGORIES) {
      const items = this.raw[category] || []
      out[category] = await Promise.all(items.map((it) => this.decryptStorable(category, it)))
    }
    return out
  }

  /**
   * Prepara el alta de un storable nuevo. Espejo de
   * `VaultCryptoService.addStorable`: cifra los campos y el título, genera el
   * `internalId` a partir del contenido cifrado y devuelve el cuerpo listo para
   * `POST /acheron/storables` más el item en claro para el estado local.
   *
   * @param {string} category  p.ej. "accounts"
   * @param {string} title
   * @param {Record<string,string>} plainFields  campos sensibles en claro
   * @returns {Promise<{ payload: object, item: object }>}
   */
  async createStorable(category, title, plainFields) {
    const now = new Date().toISOString()
    const plainItem = { title, createdAt: now, updatedAt: now, ...plainFields }
    const encrypted = await this.encryptStorable(category, plainItem)
    const internalId = await generateInternalId(category, encrypted)

    const payload = {
      kind: KIND_BY_CATEGORY[category],
      internalId,
      title: encrypted.title,
      createdAt: now,
      updatedAt: now,
    }
    for (const field of STORABLE_FIELDS[category]) {
      payload[field] = encrypted[field]
    }

    const item = { id: internalId, allowedUsers: [], ...plainItem }
    return { payload, item }
  }

  /**
   * Prepara la edición de un storable. Espejo de
   * `VaultCryptoService.updateStorable`: cifra SOLO los campos realmente
   * modificados (incluido el título) y devuelve el mapa de cambios para
   * `PATCH /acheron/storables` más el item en claro actualizado.
   *
   * `newFields` solo debe contener los campos a considerar; comparar con el
   * valor actual evita reenviar lo que no cambió.
   *
   * @param {string} category
   * @param {object} item       item en claro actual
   * @param {string} newTitle
   * @param {Record<string,string>} newFields
   * @returns {Promise<{ changes: object, item: object }>}
   */
  async buildUpdateChanges(category, item, newTitle, newFields) {
    const changes = {}
    const updated = { ...item }

    if (newTitle != null && newTitle !== item.title) {
      changes.title = await aesGcmEncrypt(this.vaultKey, newTitle)
      updated.title = newTitle
    }
    for (const [field, value] of Object.entries(newFields)) {
      if (value != null && value !== item[field]) {
        changes[field] = await aesGcmEncrypt(this.vaultKey, value)
        updated[field] = value
      }
    }
    if (Object.keys(changes).length > 0) {
      updated.updatedAt = new Date().toISOString()
    }
    return { changes, item: updated }
  }
}

/**
 * Genera un `internalId` de 16 hex a partir del SHA-256 del contenido cifrado,
 * igual que `VaultObject.generateIdFromContent`. El IV aleatorio de AES-GCM
 * hace que el id sea único por alta.
 */
async function generateInternalId(category, encrypted) {
  const parts = ['title', ...STORABLE_FIELDS[category]].map((f) => encrypted[f] ?? '')
  const hex = await sha256Hex(parts.join('|'))
  return hex.slice(0, 16)
}

/**
 * Aplica `op` (cifrar o descifrar) a `title` y a los campos sensibles de la
 * categoría, dejando intactos los metadatos (id, createdAt, updatedAt, ...).
 */
async function transformStorable(vaultKey, category, item, op) {
  const fields = STORABLE_FIELDS[category]
  if (!fields) {
    throw new Error(`Categoría de storable desconocida: ${category}`)
  }

  const result = { ...item }
  const targets = item.title != null ? ['title', ...fields] : fields
  for (const field of targets) {
    if (item[field] != null) {
      result[field] = await op(vaultKey, item[field])
    }
  }
  return result
}
