/**
 * Primitivas criptográficas del cliente web de Acheron.
 *
 * Es el espejo en JavaScript de `VaultEncryptingStrategy.java` (y de las
 * estrategias Argon2/PBKDF2). No comparte código con AcheronCore: implementa
 * EXACTAMENTE el mismo formato de cable para ser interoperable.
 *
 *   - AES-GCM 256: IV de 12 bytes aleatorio, tag de 128 bits,
 *     salida = Base64(IV ‖ ciphertext+tag).
 *   - KDF declarado por el propio vault: Argon2id (via hash-wasm) o
 *     PBKDF2-HMAC-SHA256 (nativo, Web Crypto).
 *   - vaultKey: clave AES de 32 bytes envuelta cifrando su base64 con la
 *     derivedKey.
 *   - checker: AES-GCM(derivedKey) de hex(SHA-256(username)).
 *
 * Todo corre en el navegador (Web Crypto API). El servidor es zero-knowledge:
 * nunca ve el master password ni el texto plano.
 */

import { argon2id } from 'hash-wasm'

const IV_LENGTH = 12 // bytes
const TAG_LENGTH = 128 // bits

const subtle = globalThis.crypto.subtle

/* ── helpers de codificación ─────────────────────────────────────────── */

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

/** UTF-8: string → Uint8Array */
export function utf8(str) {
  return textEncoder.encode(str)
}

/** UTF-8: Uint8Array → string */
export function fromUtf8(bytes) {
  return textDecoder.decode(bytes)
}

/** Uint8Array → string Base64 (estándar, mismo alfabeto que java.util.Base64). */
export function b64encode(bytes) {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

/** string Base64 → Uint8Array */
export function b64decode(b64) {
  const binary = atob(b64)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i)
  }
  return out
}

/** n bytes criptográficamente aleatorios. */
export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n))
}

/**
 * Genera un salt aleatorio en Base64. Espejo de `CryptoUtils.generateSalt`
 * (16 bytes = 128 bits por defecto).
 *
 * @param {number} length  longitud en bytes (mínimo 16 recomendado)
 * @returns {string} salt Base64
 */
export function generateSaltB64(length = 16) {
  return b64encode(randomBytes(length))
}

/* ── derivación de clave (KDF) ───────────────────────────────────────── */

/**
 * Deriva la clave maestra (derivedKey) desde el master password y el bloque
 * `algorithm` del vault JSON. Devuelve un CryptoKey de AES-GCM utilizable
 * para envolver/desenvolver la vaultKey y el checker.
 *
 * Despacha por `algorithm.kdf` igual que `VaultFactory.buildStrategy`.
 *
 * @param {string} masterPassword
 * @param {object} algorithm  bloque `algorithm` del vault JSON
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKey(masterPassword, algorithm) {
  const saltBytes = b64decode(algorithm.salt)
  // La API exporta los parámetros KDF como STRING; normalizamos con parseInt.
  const iterations = parseInt(algorithm.kdfIterations, 10) || 0
  const kdf = String(algorithm.kdf || '').toUpperCase()

  let rawKey // Uint8Array de 32 bytes
  if (kdf === 'PBKDF2') {
    rawKey = await deriveKeyPbkdf2(masterPassword, saltBytes, iterations || 600000)
  } else {
    // Argon2id v1.3 con los mismos defaults que AcheronCore.
    rawKey = await argon2id({
      password: utf8(masterPassword),
      salt: saltBytes,
      iterations: iterations || 3,
      memorySize: parseInt(algorithm.kdfMemoryKiB, 10) || 65536, // KiB
      parallelism: parseInt(algorithm.kdfParallelism, 10) || 1,
      hashLength: 32,
      outputType: 'binary',
    })
  }

  return subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

async function deriveKeyPbkdf2(masterPassword, saltBytes, iterations) {
  const baseKey = await subtle.importKey('raw', utf8(masterPassword), 'PBKDF2', false, [
    'deriveBits',
  ])
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
    baseKey,
    256, // bits → AES-256
  )
  return new Uint8Array(bits)
}

/* ── AES-GCM (cifrado de datos) ──────────────────────────────────────── */

/**
 * Cifra texto plano con AES-GCM y la clave dada.
 * Salida = Base64(IV(12) ‖ ciphertext+tag). Espejo de `encryptWithKey`.
 *
 * @param {CryptoKey} key
 * @param {string} plainText
 * @returns {Promise<string>}
 */
export async function aesGcmEncrypt(key, plainText) {
  const iv = randomBytes(IV_LENGTH)
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: TAG_LENGTH }, key, utf8(plainText)),
  )
  const out = new Uint8Array(iv.length + ct.length)
  out.set(iv, 0)
  out.set(ct, iv.length)
  return b64encode(out)
}

/**
 * Descifra Base64(IV ‖ ciphertext+tag) con AES-GCM. Espejo de `decryptWithKey`.
 *
 * @param {CryptoKey} key
 * @param {string} ivAndCiphertextB64
 * @returns {Promise<string>}
 * @throws si el tag no valida (clave/IV incorrectos)
 */
export async function aesGcmDecrypt(key, ivAndCiphertextB64) {
  const buf = b64decode(ivAndCiphertextB64)
  const iv = buf.slice(0, IV_LENGTH)
  const ct = buf.slice(IV_LENGTH)
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: TAG_LENGTH }, key, ct)
  return fromUtf8(new Uint8Array(plain))
}

/* ── vaultKey (envoltura de la clave del vault) ──────────────────────── */

/**
 * Desenvuelve la vaultKey: descifra el blob con la derivedKey (lo que se
 * obtiene es el base64 de la clave AES cruda), lo decodifica e importa como
 * CryptoKey de AES-GCM. Espejo de `importVaultKey`.
 *
 * @param {CryptoKey} derivedKey
 * @param {string} vaultKeyB64  campo `vaultKey` del vault JSON
 * @returns {Promise<CryptoKey>}
 */
export async function importVaultKey(derivedKey, vaultKeyB64) {
  const rawKeyB64 = await aesGcmDecrypt(derivedKey, vaultKeyB64)
  const rawKey = b64decode(rawKeyB64)
  return subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

/* ── checker (validación del master password) ────────────────────────── */

/** hex(SHA-256(str)). Espejo del hash que produce AcheronCore para el checker. */
export async function sha256Hex(str) {
  const digest = new Uint8Array(await subtle.digest('SHA-256', utf8(str)))
  let hex = ''
  for (let i = 0; i < digest.length; i++) {
    hex += digest[i].toString(16).padStart(2, '0')
  }
  return hex
}

/**
 * Valida el master password: descifra el `checker` con la derivedKey y lo
 * compara con hex(SHA-256(username)). Espejo de `VaultFactory.checkMasterPassword`.
 *
 * @param {CryptoKey} derivedKey
 * @param {string} checker  campo `checker` del vault JSON
 * @param {string} username validator (username del usuario logueado)
 * @returns {Promise<boolean>}
 */
export async function validateChecker(derivedKey, checker, username) {
  let decrypted
  try {
    decrypted = await aesGcmDecrypt(derivedKey, checker)
  } catch {
    // Tag inválido = master password incorrecto, no un error genérico.
    return false
  }
  return decrypted === (await sha256Hex(username))
}
