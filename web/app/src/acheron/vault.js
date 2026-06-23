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
} from './crypto.js'
import { STORABLE_FIELDS, STORABLE_CATEGORIES } from './storableFields.js'

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
