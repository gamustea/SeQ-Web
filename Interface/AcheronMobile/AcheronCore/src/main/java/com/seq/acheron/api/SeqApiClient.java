package com.seq.acheron.api;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Properties;

/**
 * Cliente HTTP para la API REST de SeQ ({@code api.seq.com}).
 * <p>
 * Implementa el flujo OAuth 2.0 de la plataforma SeQ:
 * <ul>
 *   <li><b>Access token</b>: JWT firmado con HS256, vida corta
 *       (configurable en el servidor, por defecto 15 minutos).</li>
 *   <li><b>Refresh token</b>: token opaco URL-safe, vida larga
 *       (por defecto 30 días), almacenado en base de datos.</li>
 * </ul>
 * El cliente gestiona ambos tokens de forma transparente:
 * tras llamar a {@link #login(String, String)}, el access token
 * se adjunta automáticamente en cada petición. Cuando expira,
 * llama a {@link #refresh()} con el refresh token para obtener
 * uno nuevo sin necesidad de re-autenticar al usuario.
 * <p>
 * Las URLs de los endpoints se cargan desde {@code api.properties}
 * en el classpath, sin ninguna dirección hard-codeada en el código.
 * <p>
 * Ejemplo de uso:
 * <pre>{@code
 *   SeqApiClient client = new SeqApiClient();
 *
 *   // 1. Login — obtiene y almacena ambos tokens internamente
 *   client.login("gabriel", "miContraseña");
 *
 *   // 2. Llamadas autenticadas
 *   HttpResponse<String> vault = client.get(client.url("api.url.vault.get"));
 *
 *   // 3. Renovar access token con el refresh token
 *   client.refresh();
 *
 *   // 4. Logout — revoca el access token en el servidor
 *   client.logout();
 * }</pre>
 *
 * @see OAuthTokens
 */
public class SeqApiClient {

    // ------------------------------------------------------------------ //
    //  Constantes                                                          //
    // ------------------------------------------------------------------ //

    /** Nombre del archivo de configuración de endpoints en el classpath. */
    private static final String PROPERTIES_FILE = "api.properties";

    /** Cabecera HTTP utilizada para enviar el Bearer token. */
    private static final String AUTH_HEADER = "Authorization";

    /** Content-Type por defecto para peticiones con cuerpo. */
    private static final String JSON = "application/json";

    // ------------------------------------------------------------------ //
    //  Campos                                                              //
    // ------------------------------------------------------------------ //

    /** Endpoints y timeouts cargados desde {@code api.properties}. */
    private final Properties props;

    /** Cliente HTTP subyacente, thread-safe y reutilizable. */
    private final HttpClient http;

    /**
     * Par de tokens activo tras un login exitoso.
     * {@code null} si el cliente aún no ha autenticado al usuario.
     */
    @Nullable
    private OAuthTokens tokens;

    // ------------------------------------------------------------------ //
    //  Constructor                                                         //
    // ------------------------------------------------------------------ //

    /**
     * Crea un nuevo {@code SeqApiClient} cargando la configuración de
     * endpoints desde {@code api.properties} en el classpath y construyendo
     * el {@link HttpClient} con los timeouts configurados.
     *
     * @throws IllegalStateException si {@code api.properties} no existe
     *                               o no puede leerse
     */
    public SeqApiClient() {
        this.props = loadAndResolveProperties();
        this.http  = buildHttpClient();
    }

    // ------------------------------------------------------------------ //
    //  OAuth – flujo principal                                             //
    // ------------------------------------------------------------------ //

    /**
     * Autentica al usuario contra {@code POST /auth/login} y almacena
     * internamente el access token JWT y el refresh token opaco devueltos
     * por el servidor.
     * <p>
     * El cuerpo de la petición tiene el formato:
     * <pre>{@code {"username": "...", "password": "..."}}</pre>
     * El servidor devuelve:
     * <pre>{@code {"access_token": "...", "refresh_token": "..."}}</pre>
     *
     * @param username nombre de usuario registrado en SeQ
     * @param password contraseña en texto plano
     * @return respuesta HTTP raw del servidor (útil para comprobar errores)
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> login(
            @NotNull String username,
            @NotNull String password
    ) throws IOException, InterruptedException {

        String body = String.format(
                "{\"username\":\"%s\",\"password\":\"%s\"}",
                username, password
        );

        HttpResponse<String> response = postNoAuth(url("api.url.auth.login"), body);

        if (response.statusCode() == 200) {
            this.tokens = OAuthTokens.parse(response.body());
        }
        return response;
    }

    /**
     * Renueva el access token llamando a {@code POST /auth/refresh} con el
     * refresh token opaco almacenado.
     * <p>
     * Debe llamarse cuando el access token haya expirado (el servidor
     * devolverá HTTP 401 con un cuerpo que indica token expirado).
     * Tras una renovación exitosa, el nuevo access token se almacena
     * automáticamente y las siguientes peticiones lo usarán.
     *
     * @return respuesta HTTP raw del servidor
     * @throws IOException              si ocurre un error de red
     * @throws InterruptedException     si la operación es interrumpida
     * @throws IllegalStateException    si no hay sesión activa (no se ha
     *                                  hecho login previamente)
     */
    @NotNull
    public HttpResponse<String> refresh()
            throws IOException, InterruptedException {

        requireSession();

        String body = String.format(
                "{\"refresh_token\":\"%s\"}",
                tokens.getRefreshToken()  // NON-NULL: requireSession() lo garantiza
        );

        HttpResponse<String> response = postNoAuth(url("api.url.auth.refresh"), body);

        if (response.statusCode() == 200) {
            OAuthTokens renewed = OAuthTokens.parse(response.body());
            // El servidor puede devolver solo el nuevo access token o ambos
            this.tokens = new OAuthTokens(
                    renewed.getAccessToken(),
                    renewed.getRefreshToken() != null
                            ? renewed.getRefreshToken()
                            : tokens.getRefreshToken()
            );
        }
        return response;
    }

    /**
     * Cierra la sesión del usuario llamando a {@code POST /auth/logout},
     * que revoca el access token activo en el servidor, y limpia los tokens
     * almacenados localmente.
     *
     * @return respuesta HTTP raw del servidor
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     * @throws IllegalStateException si no hay sesión activa
     */
    @NotNull
    public HttpResponse<String> logout()
            throws IOException, InterruptedException {

        requireSession();
        HttpResponse<String> response = post(url("api.url.auth.logout"), "{}");

        if (response.statusCode() == 200) {
            this.tokens = null;
        }

        return response;
    }

    /**
     * Revoca <em>todos</em> los tokens activos del usuario en el servidor
     * llamando a {@code POST /auth/revoke-all} (logout global / cierre de
     * todas las sesiones). Útil tras un cambio de contraseña o detección
     * de acceso no autorizado.
     *
     * @return respuesta HTTP raw del servidor
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     * @throws IllegalStateException si no hay sesión activa
     */
    @NotNull
    public HttpResponse<String> revokeAllTokens()
            throws IOException, InterruptedException {

        requireSession();
        HttpResponse<String> response = post(url("api.url.auth.revoke-all"), "{}");

        if (response.statusCode() == 200) {
            this.tokens = null;
        }

        return response;
    }

    // ------------------------------------------------------------------ //
    //  Vault (Acheron)                                                     //
    // ------------------------------------------------------------------ //

    /**
     * Obtiene el vault cifrado del usuario autenticado.
     * {@code GET /acheron/vault}
     *
     * @return respuesta con el JSON del vault serializado
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> getVault()
            throws IOException, InterruptedException {
        return get(url("api.url.vault.get"));
    }

    /**
     * Guarda o actualiza el vault cifrado del usuario autenticado.
     * {@code PUT /acheron/vault}
     *
     * @param vaultJson JSON del vault serializado (salida de
     *                  {@link com.seq.acheron.vault.Vault#toJson()})
     * @return respuesta HTTP del servidor
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> saveVault(@NotNull String vaultJson)
            throws IOException, InterruptedException {
        return put(url("api.url.vault.save"), vaultJson);
    }

    /**
     * Elimina el vault del usuario autenticado en el servidor.
     * {@code DELETE /acheron/vault}
     *
     * @return respuesta HTTP del servidor
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> deleteVault()
            throws IOException, InterruptedException {
        return delete(url("api.url.vault.delete"));
    }

    /**
     * Envía un vault de restauración al servidor.
     * {@code POST /acheron/vault/restore}
     * <p>
     * El cuerpo debe incluir el vault de restauración serializado y la
     * contraseña temporal generada por
     * {@link com.seq.acheron.vault.VaultFactory#getRestorationVault}.
     *
     * @param restorePayloadJson JSON con {@code vault} y
     *                           {@code restoration_password}
     * @return respuesta HTTP del servidor
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> restoreVault(@NotNull String restorePayloadJson)
            throws IOException, InterruptedException {
        return post(url("api.url.vault.restore"), restorePayloadJson);
    }
    // ------------------------------------------------------------------ //
    //  Usuarios (Acheron)                                                  //
    // ------------------------------------------------------------------ //

    /**
     * Registra un nuevo usuario en la plataforma SeQ.
     * {@code POST /acheron/users/register}
     * <p>
     * El cuerpo esperado es:
     * <pre>{@code
     * {
     *   "username":   "gabriel",
     *   "password":   "...",
     *   "email":      "gabriel@seq.com",
     *   "first_name": "Gabriel",
     *   "last_name":  "Musteata",
     *   "alias":      "gamustea"
     * }
     * }</pre>
     *
     * @param registerJson JSON con los datos del nuevo usuario
     * @return respuesta HTTP del servidor
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> registerUser(@NotNull String registerJson)
            throws IOException, InterruptedException {
        return postNoAuth(url("api.url.user.register"), registerJson);
    }

    /**
     * Obtiene el perfil del usuario autenticado.
     * {@code GET /acheron/users/me}
     *
     * @return respuesta con el JSON del perfil de usuario
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> getMe()
            throws IOException, InterruptedException {
        return get(url("api.url.user.me"));
    }

    /**
     * Actualiza los datos del usuario autenticado.
     * {@code PUT /acheron/users/me}
     *
     * @param updateJson JSON con los campos a actualizar
     * @return respuesta HTTP del servidor
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> updateMe(@NotNull String updateJson)
            throws IOException, InterruptedException {
        return put(url("api.url.user.me"), updateJson);
    }

    /**
     * Elimina la cuenta del usuario autenticado.
     * {@code DELETE /acheron/users/me}
     * <p>
     * Esta operación es irreversible. Revoca también todos los tokens
     * activos y limpia la sesión local.
     *
     * @return respuesta HTTP del servidor
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> deleteMe()
            throws IOException, InterruptedException {
        HttpResponse<String> response = delete(url("api.url.user.me"));
        if (response.statusCode() == 200) {
            this.tokens = null;
        }
        return response;
    }

    /**
     * Cambia la contraseña del usuario autenticado.
     * {@code PUT /acheron/users/me/password}
     * <p>
     * El cuerpo esperado es:
     * <pre>{@code
     * {
     *   "current_password": "...",
     *   "new_password":     "..."
     * }
     * }</pre>
     * Tras un cambio de contraseña exitoso se recomienda llamar a
     * {@link #revokeAllTokens()} para cerrar todas las sesiones activas.
     *
     * @param passwordJson JSON con la contraseña actual y la nueva
     * @return respuesta HTTP del servidor
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> changePassword(@NotNull String passwordJson)
            throws IOException, InterruptedException {
        return put(url("api.url.user.password"), passwordJson);
    }

    // ------------------------------------------------------------------ //
    //  Estado de sesión                                                    //
    // ------------------------------------------------------------------ //

    /**
     * Indica si el cliente tiene una sesión activa (tokens almacenados).
     *
     * @return {@code true} si el usuario ha hecho login y los tokens
     *         no han sido limpiados explícitamente
     */
    public boolean isAuthenticated() {
        return tokens != null;
    }

    /**
     * Devuelve los tokens OAuth activos, o {@code null} si no hay sesión.
     *
     * @return par de tokens activo, puede ser {@code null}
     */
    @Nullable
    public OAuthTokens getTokens() {
        return tokens;
    }

    // ------------------------------------------------------------------ //
    //  Resolución de URLs                                                  //
    // ------------------------------------------------------------------ //

    /**
     * Resuelve la URL de un endpoint por su clave de propiedad.
     * <p>
     * Ejemplo: {@code url("api.url.vault.get")} devuelve
     * {@code "https://api.seq.com/v1/acheron/vault"}.
     * <p>
     * Para endpoints con parámetros de ruta como {@code {id}}, sustituye
     * el placeholder antes de llamar a los métodos HTTP:
     * <pre>{@code
     * String endpoint = client.url("api.url.scan.status").replace("{id}", String.valueOf(scanId));
     * client.get(endpoint);
     * }</pre>
     *
     * @param key clave definida en {@code api.properties}
     * @return URL resuelta
     * @throws IllegalArgumentException si la clave no existe en el archivo
     */
    @NotNull
    public String url(@NotNull String key) {
        String value = props.getProperty(key);
        if (value == null) {
            throw new IllegalArgumentException(
                    "Clave '" + key + "' no encontrada en " + PROPERTIES_FILE
            );
        }
        return value;
    }

    // ------------------------------------------------------------------ //
    //  Métodos HTTP autenticados (públicos para uso avanzado)              //
    // ------------------------------------------------------------------ //

    /**
     * Envía una petición HTTP GET autenticada con el Bearer token activo.
     *
     * @param url URL del endpoint
     * @return respuesta HTTP con cuerpo {@code String}
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> get(@NotNull String url)
            throws IOException, InterruptedException {
        return send(baseRequest(url).GET().build());
    }

    /**
     * Envía una petición HTTP POST autenticada con cuerpo JSON.
     *
     * @param url  URL del endpoint
     * @param body cuerpo JSON
     * @return respuesta HTTP con cuerpo {@code String}
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> post(@NotNull String url, @NotNull String body)
            throws IOException, InterruptedException {
        HttpRequest req = baseRequest(url)
                .header("Content-Type", JSON)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return send(req);
    }

    /**
     * Envía una petición HTTP PUT autenticada con cuerpo JSON.
     *
     * @param url  URL del endpoint
     * @param body cuerpo JSON
     * @return respuesta HTTP con cuerpo {@code String}
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> put(@NotNull String url, @NotNull String body)
            throws IOException, InterruptedException {
        HttpRequest req = baseRequest(url)
                .header("Content-Type", JSON)
                .PUT(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return send(req);
    }

    /**
     * Envía una petición HTTP DELETE autenticada.
     *
     * @param url URL del endpoint
     * @return respuesta HTTP con cuerpo {@code String}
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    public HttpResponse<String> delete(@NotNull String url)
            throws IOException, InterruptedException {
        return send(baseRequest(url).DELETE().build());
    }

    // ------------------------------------------------------------------ //
    //  Helpers privados                                                    //
    // ------------------------------------------------------------------ //

    /**
     * Construye un {@link HttpRequest.Builder} base con:
     * <ul>
     *   <li>{@code Accept: application/json}</li>
     *   <li>{@code Authorization: Bearer <accessToken>} si hay sesión activa</li>
     * </ul>
     *
     * @param url URL destino
     * @return builder preconfigurado
     */
    @NotNull
    private HttpRequest.Builder baseRequest(@NotNull String url) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", JSON);

        if (tokens != null && tokens.getAccessToken() != null) {
            builder.header(AUTH_HEADER, "Bearer " + tokens.getAccessToken());
        }

        return builder;
    }

    /**
     * Envía una petición POST <em>sin</em> cabecera de autorización.
     * Usado internamente para {@link #login(String, String)} y
     * {@link #refresh()}, que no disponen aún de access token válido.
     *
     * @param url  URL del endpoint
     * @param body cuerpo JSON
     * @return respuesta HTTP con cuerpo {@code String}
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    private HttpResponse<String> postNoAuth(@NotNull String url, @NotNull String body)
            throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", JSON)
                .header("Content-Type", JSON)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return send(req);
    }

    /**
     * Envía la petición usando el {@link HttpClient} subyacente y registra
     * el método, la URI y el código de respuesta en el log de debug.
     *
     * @param request petición completamente construida
     * @return respuesta del servidor
     * @throws IOException          si ocurre un error de red
     * @throws InterruptedException si la operación es interrumpida
     */
    @NotNull
    private HttpResponse<String> send(@NotNull HttpRequest request)
            throws IOException, InterruptedException {
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Verifica que haya una sesión activa. Lanza {@link IllegalStateException}
     * si no se ha llamado a {@link #login(String, String)} previamente o si
     * los tokens han sido limpiados tras un logout.
     *
     * @throws IllegalStateException si no hay sesión activa
     */
    private void requireSession() {
        if (tokens == null) {
            throw new IllegalStateException(
                    "No hay sesión activa. Llama a login() primero."
            );
        }
    }

    /**
     * Carga {@code api.properties} desde el classpath y resuelve referencias
     * del tipo {@code ${clave}} en los valores (interpolación de un único nivel,
     * suficiente para la estructura plana del archivo).
     *
     * @return {@link Properties} con todos los valores resueltos
     * @throws IllegalStateException si el archivo no existe o no puede leerse
     */
    @NotNull
    private Properties loadAndResolveProperties() {
        Properties raw = new Properties();

        try (InputStream is = getClass()
                .getClassLoader()
                .getResourceAsStream(PROPERTIES_FILE)) {

            if (is == null) {
                throw new IllegalStateException(
                        PROPERTIES_FILE + " no encontrado en el classpath"
                );
            }
            raw.load(is);

        } catch (IOException e) {
            throw new IllegalStateException("Error leyendo " + PROPERTIES_FILE, e);
        }

        // Resolver ${clave} → valor
        Properties resolved = new Properties();
        for (String key : raw.stringPropertyNames()) {
            String value = raw.getProperty(key);
            for (String ref : raw.stringPropertyNames()) {
                value = value.replace("${" + ref + "}", raw.getProperty(ref));
            }
            resolved.setProperty(key, value);
        }
        return resolved;
    }

    /**
     * Construye el {@link HttpClient} con el timeout de conexión definido
     * en {@code api.properties}.
     *
     * @return cliente HTTP configurado
     */
    @NotNull
    private HttpClient buildHttpClient() {
        int connectMs = Integer.parseInt(
                props.getProperty("api.timeout.connect", "5000")
        );
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(connectMs))
                .build();
    }
}
