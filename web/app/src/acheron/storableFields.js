/**
 * Registro data-driven de los campos sensibles de cada tipo de storable.
 *
 * Es la versión JS, en un único sitio, de los métodos `transform()` de cada
 * storable de AcheronCore (Account, CreditCard, ...). Las claves son las
 * categorías tal y como aparecen en el vault JSON que devuelve `GET /vault`.
 *
 * Cada campo listado va cifrado individualmente como Base64(IV‖ct).
 * Además, `title` SIEMPRE va cifrado (lo añade `vault.js`).
 * Los metadatos `id`, `createdAt`, `updatedAt`, `allowedUsers` van en claro.
 *
 * Análogo al registro `StorableTypes.kt` del móvil: para añadir un tipo nuevo
 * basta con añadir aquí su categoría y sus campos sensibles.
 */
export const STORABLE_FIELDS = {
  accounts: ['username', 'domain', 'password'],
  creditcards: ['cardHolderName', 'cardNumber', 'expirationDate', 'postalCode', 'cvv'],
  securenotes: ['content'],
  identities: ['fullName', 'email', 'phone', 'address', 'city', 'country', 'documentId'],
  bankaccounts: ['bankName', 'holder', 'iban', 'swiftBic', 'accountNumber'],
  wifinetworks: ['ssid', 'password', 'securityType'],
  licenses: ['product', 'licenseKey', 'licensedTo', 'version'],
}

/** Las categorías de storables presentes en un vault JSON. */
export const STORABLE_CATEGORIES = Object.keys(STORABLE_FIELDS)
