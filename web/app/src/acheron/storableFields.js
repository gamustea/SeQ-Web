/**
 * Vista que necesita la capa cripto: qué campos sensibles tiene cada categoría
 * y las correspondencias categoría↔kind. Se DERIVA del registro único
 * `storableTypes.js` para que no pueda divergir de la UI ni del móvil.
 *
 * Cada campo aquí listado se cifra individualmente como Base64(IV‖ct). Además,
 * `title` SIEMPRE va cifrado (lo añade `vault.js`). Los metadatos `id`,
 * `createdAt`, `updatedAt`, `allowedUsers` van en claro.
 */
import { STORABLE_TYPES } from './storableTypes.js'

/** category → array de claves de campos sensibles. */
export const STORABLE_FIELDS = Object.fromEntries(
  STORABLE_TYPES.map((t) => [t.category, t.fields.map((f) => f.key)]),
)

/** Las categorías de storables presentes en un vault JSON, en orden. */
export const STORABLE_CATEGORIES = STORABLE_TYPES.map((t) => t.category)

/** category (plural, vault JSON) → kind (singular, API `POST /storables`). */
export const KIND_BY_CATEGORY = Object.fromEntries(
  STORABLE_TYPES.map((t) => [t.category, t.kind]),
)

/** kind → category. */
export const CATEGORY_BY_KIND = Object.fromEntries(
  STORABLE_TYPES.map((t) => [t.kind, t.category]),
)
