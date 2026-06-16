# Mejoras detectadas durante la creación de tests

Documento vivo con hallazgos encontrados al escribir la suite de tests. **No se
ha modificado `src/`**; aquí quedan registrados para decisión posterior.
Orden aproximado por severidad.

## Alta

### 1. `require_attributes` se traga las excepciones de dominio → 500 en vez de 404/409
`src/modules/users/services/permissions.py:380-385` envuelve la llamada al handler
en un `except Exception` genérico que captura cualquier `SecOpsException`
(`ScanNotFoundError`, `IrisAnalysisNotFoundError`, `DocumentError`,
`VaultNotFoundError`, `FolderNotFoundError`, …) lanzada **dentro** del endpoint y
responde `500 server_error`. Esto rompe TODOS los `alt_response(404/409)` de los
endpoints protegidos por atributos.
- **Impacto:** los "no encontrado" / "no listo" devuelven 500.
- **Tests que lo evidencian:** `test_scan_detail_not_found`,
  `test_iris.py::test_status_unknown_analysis_returns_404`,
  `test_aegis.py::test_status_unknown_document_returns_404`,
  `test_acheron.py::test_get_vault_empty_returns_404`,
  `test_folder_isolation_between_users` (todos `xfail(strict)`).
- **Sugerencia:** capturar solo excepciones inesperadas y re-lanzar
  `SecOpsException` (o no envolver la llamada a `f`), dejando que el errorhandler
  global formatee el código correcto.

### 2. Tokens JWT deterministas → colisión con la constraint UNIQUE
`src/modules/users/managers.py:527-544` firma el access token con `iat`/`exp` a
resolución de **segundo**. Dos tokens del mismo usuario emitidos en el mismo
segundo (login + refresh, o varias peticiones seguidas) generan exactamente el
mismo string y violan `UNIQUE (AccessToken.token)` → `IntegrityError`.
- **Sugerencia:** añadir un claim único (`jti = uuid4`) al payload, o usar
  precisión de microsegundo. La suite aplica un parche de test equivalente
  (`tests/conftest.py`).

### 3. `pages.serve_page` no aplica autenticación pese a documentarlo
`src/modules/pages/endpoints.py:62-70` sirve páginas arbitrarias sin
`@require_oauth_token`, aunque el docstring afirma que requieren token OAuth.
- **Impacto:** posible exposición de páginas que se asumen protegidas.

### 4. Hashing de contraseñas débil y comparación no constante
`src/modules/users/services/secrets.py`: usa SHA-256 con salt (sin
PBKDF2/bcrypt/argon2 ni stretching) y `verify_password` compara con `==` (no
`hmac.compare_digest`), pese a que los docstrings de `managers.py` afirman
"constant-time comparison" y "pbkdf2".
- **Sugerencia:** migrar a `argon2`/`bcrypt` y comparación en tiempo constante.

## Media

### 5. `get_app_context()` lanza ValueError espurio con los defaults
`src/modules/system/config_reading.py:157-173`: `all([... create_database, debug ...])`
trata el `bool False` por defecto como "ausente" y lanza `ValueError`; además
mezcla comparación bool vs string (`== "true"`). Importar `run.py` sin definir
`DEBUG`/`CREATE_DATABASE` falla. (Test: `test_config_reading.py`.)

### 6. `isolation_level="READ COMMITTED"` codificado, no portable
`shared/_managers.py:148-154` y `infrastructure/unit_of_work.py:87-93` fijan un
nivel de aislamiento válido en PostgreSQL pero rechazado por SQLite (rompe tests
y cualquier otro dialecto). Considerar hacerlo configurable.

### 7. Doble bootstrap de engine/sesión duplicado
La inicialización de engine + `scoped_session` está duplicada en
`shared/_managers.py` y `infrastructure/unit_of_work.py` (dos singletons sobre la
misma BD). Riesgo de divergencia y de dos pools. Unificar en un único módulo.

### 8. `VaultNotFoundError()` se instancia sin el argumento requerido
`src/modules/acheron/endpoints.py:58,162` llama `VaultNotFoundError()` pero el
`__init__` exige `vault_id` → `TypeError` (otro 500). 

### 9. Doble prefijo en rutas de Acheron
El blueprint se registra con `url_prefix="/acheron"` y las rutas declaran de nuevo
`/acheron/...`, resultando en `/acheron/acheron/vault`. Probablemente no
intencionado.

### 10. Interpolación de SQL con f-strings en `_init_db`
`run.py:438-477` construye SQL con f-strings (nombres de BD, atributos). Aunque es
una ruta administrativa/interna, es un patrón de inyección; usar parámetros.

## Baja

### 11. `AttributeType.db_description` está roto
`src/modules/users/services/permissions.py:133-135`: `self._DESCRIPTIONS` no
resuelve al dict dentro del Enum (lanza `AttributeError`). El método nunca
funciona. (Test: `test_permissions.py`.)

### 12. `get_current_user()` con caché rota
`src/modules/users/endpoints.py:48-54`: comprueba `hasattr(request, 'current_user')`
pero nunca lo asigna; la variable `user` podría quedar sin definir en la rama
"cacheada". Funciona por casualidad porque la condición siempre es falsa.

### 13. `redis.ping` con timeout de 5 s en cada `create_app`
`run.py:255-270`: penaliza el arranque (y los tests) cuando Redis no está. Podría
ser perezoso/opcional.

### 14. Typos y mezcla de idiomas en logs
P. ej. `"Se obtained {n} ..."`, `"Error obtaining ..."` en `shared/_managers.py`.
