/**
 * Registro data-driven de los tipos de storable de Acheron.
 *
 * Espejo en JS de `StorableTypes.kt` de la app móvil: es la ÚNICA fuente de
 * verdad para la UI (formulario, lista, detalle) y, derivado, para la capa
 * cripto (`storableFields.js`). Añadir un tipo nuevo = añadir una entrada aquí.
 *
 * Por cada campo:
 *   - key:       nombre del campo (coincide con el vault JSON y con la API).
 *   - label:     etiqueta legible (idéntica a la del móvil).
 *   - secret:    se enmascara en el detalle y se escribe como contraseña.
 *   - prefill:   en EDICIÓN se pre-rellena con el valor actual. Los secretos
 *                sensibles (contraseña, PAN, CVV) van a false: se dejan en
 *                blanco y solo se reescriben si el usuario teclea algo.
 *   - numeric:   teclado/inputmode numérico.
 *   - multiline: textarea (notas).
 *   - minLength: longitud mínima exigida cuando el campo lleva valor.
 *
 * `category` es la clave plural usada en el vault JSON (`accounts`, ...);
 * `kind` es el singular que espera la API en `POST /storables` (`account`, ...).
 */
export const STORABLE_TYPES = [
  {
    kind: 'account', category: 'accounts',
    label: 'Cuenta', plural: 'Cuentas', newLabel: 'Nueva cuenta', subtitleKey: 'username',
    fields: [
      { key: 'username', label: 'Usuario / Email' },
      { key: 'domain', label: 'Dominio / Servicio' },
      { key: 'password', label: 'Contraseña', secret: true, prefill: false },
    ],
  },
  {
    kind: 'creditcard', category: 'creditcards',
    label: 'Tarjeta', plural: 'Tarjetas', newLabel: 'Nueva tarjeta', subtitleKey: 'cardNumber',
    fields: [
      { key: 'cardHolderName', label: 'Titular' },
      { key: 'cardNumber', label: 'Número de tarjeta', secret: true, prefill: false, numeric: true, minLength: 4 },
      { key: 'expirationDate', label: 'Caducidad (MM/YY)' },
      { key: 'cvv', label: 'CVV', secret: true, prefill: false, numeric: true },
      { key: 'postalCode', label: 'Código postal' },
    ],
  },
  {
    kind: 'securenote', category: 'securenotes',
    label: 'Nota segura', plural: 'Notas', newLabel: 'Nueva nota', subtitleKey: 'content',
    fields: [
      { key: 'content', label: 'Contenido', multiline: true },
    ],
  },
  {
    kind: 'identity', category: 'identities',
    label: 'Identidad', plural: 'Identidades', newLabel: 'Nueva identidad', subtitleKey: 'fullName',
    fields: [
      { key: 'fullName', label: 'Nombre completo' },
      { key: 'email', label: 'Email' },
      { key: 'phone', label: 'Teléfono' },
      { key: 'address', label: 'Dirección' },
      { key: 'city', label: 'Ciudad' },
      { key: 'country', label: 'País' },
      { key: 'documentId', label: 'Documento (DNI/Pasaporte)', secret: true },
    ],
  },
  {
    kind: 'bankaccount', category: 'bankaccounts',
    label: 'Cuenta bancaria', plural: 'Bancos', newLabel: 'Nueva cuenta bancaria', subtitleKey: 'bankName',
    fields: [
      { key: 'bankName', label: 'Banco' },
      { key: 'holder', label: 'Titular' },
      { key: 'iban', label: 'IBAN', secret: true },
      { key: 'swiftBic', label: 'SWIFT / BIC', secret: true },
      { key: 'accountNumber', label: 'Número de cuenta', secret: true },
    ],
  },
  {
    kind: 'wifi', category: 'wifinetworks',
    label: 'Wi-Fi', plural: 'Wi-Fi', newLabel: 'Nueva red Wi-Fi', subtitleKey: 'ssid',
    fields: [
      { key: 'ssid', label: 'Nombre de red (SSID)' },
      { key: 'password', label: 'Contraseña', secret: true, prefill: false },
      { key: 'securityType', label: 'Seguridad (WPA2/WPA3)' },
    ],
  },
  {
    kind: 'license', category: 'licenses',
    label: 'Licencia', plural: 'Licencias', newLabel: 'Nueva licencia', subtitleKey: 'product',
    fields: [
      { key: 'product', label: 'Producto' },
      { key: 'licenseKey', label: 'Clave de licencia', secret: true },
      { key: 'licensedTo', label: 'Licenciado a' },
      { key: 'version', label: 'Versión' },
    ],
  },
]

/** Spec por categoría (clave plural del vault JSON). */
export const TYPE_BY_CATEGORY = Object.fromEntries(STORABLE_TYPES.map((t) => [t.category, t]))

/** Spec por kind (singular de la API). */
export const TYPE_BY_KIND = Object.fromEntries(STORABLE_TYPES.map((t) => [t.kind, t]))
