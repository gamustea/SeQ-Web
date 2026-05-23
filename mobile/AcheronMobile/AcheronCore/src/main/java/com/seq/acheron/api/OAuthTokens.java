package com.seq.acheron.api;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Contiene el par de tokens OAuth 2.0 devueltos por la API de SeQ
 * tras un login o refresh exitoso.
 * <p>
 * <b>Access token</b>: JWT firmado con HS256, de vida corta (15 min por
 * defecto). Su payload contiene {@code sub} (user_id), {@code username},
 * {@code exp}, {@code iat} y {@code type: "access"}, tal como define
 * {@code OAuthTokenManager.create_access_token()} en el servidor.
 * <p>
 * <b>Refresh token</b>: token opaco URL-safe (64 bytes), de vida larga
 * (30 días por defecto). No es un JWT; se verifica en base de datos en
 * el servidor mediante {@code OAuthTokenManager.verify_refresh_token()}.
 *
 * @see SeqApiClient
 */
@Getter
public class OAuthTokens {

    /** JWT de acceso de vida corta. */
    @NotNull
    private final String accessToken;

    /**
     * Token de refresco opaco de vida larga.
     * Puede ser {@code null} en respuestas de {@code /auth/refresh}
     * que solo renueven el access token.
     */
    @Nullable
    private final String refreshToken;

    // ------------------------------------------------------------------ //
    //  Constructor                                                         //
    // ------------------------------------------------------------------ //

    /**
     * Crea un par de tokens OAuth.
     *
     * @param accessToken  JWT de acceso; no puede ser {@code null}
     * @param refreshToken token de refresco opaco; puede ser {@code null}
     *                     si el servidor solo devuelve un access token renovado
     */
    public OAuthTokens(
            @NotNull  String accessToken,
            @Nullable String refreshToken
    ) {
        this.accessToken  = accessToken;
        this.refreshToken = refreshToken;
    }

    // ------------------------------------------------------------------ //
    //  Parseo                                                              //
    // ------------------------------------------------------------------ //

    /**
     * Parsea el JSON devuelto por {@code POST /auth/login} o
     * {@code POST /auth/refresh} y construye un {@code OAuthTokens}.
     * <p>
     * Formato esperado del servidor:
     * <pre>{@code
     * {
     *   "access_token":  "eyJhbGci...",
     *   "refresh_token": "dG9rZW5P..."   ← (opcional)
     * }
     * }</pre>
     * El parseo se realiza sin dependencias externas (sin Gson/Jackson)
     * para no añadir acoplamiento a esta clase auxiliar.
     *
     * @param json cuerpo de la respuesta HTTP del servidor
     * @return instancia construida con los tokens extraídos
     * @throws IllegalArgumentException si {@code access_token} no está
     *                                  presente en el JSON
     */
    @NotNull
    public static OAuthTokens parse(@NotNull String json) {
        String accessToken  = extractField(json, "access_token");
        String refreshToken = extractField(json, "refresh_token");

        if (accessToken == null) {
            throw new IllegalArgumentException(
                    "El JSON de respuesta no contiene 'access_token': " + json
            );
        }

        return new OAuthTokens(accessToken, refreshToken);
    }

    // ------------------------------------------------------------------ //
    //  Helpers                                                             //
    // ------------------------------------------------------------------ //

    /**
     * Extrae el valor de un campo de texto de un JSON plano sin librería
     * externa. Busca el patrón {@code "field":"value"} ignorando espacios.
     *
     * @param json  JSON en texto plano
     * @param field nombre del campo a extraer
     * @return valor del campo, o {@code null} si no existe
     */
    @Nullable
    private static String extractField(@NotNull String json, @NotNull String field) {
        String pattern = "\"" + field + "\"";
        int keyIdx = json.indexOf(pattern);
        if (keyIdx == -1) return null;

        int colonIdx = json.indexOf(':', keyIdx + pattern.length());
        if (colonIdx == -1) return null;

        int openQuote = json.indexOf('"', colonIdx + 1);
        if (openQuote == -1) return null;

        int closeQuote = json.indexOf('"', openQuote + 1);
        if (closeQuote == -1) return null;

        return json.substring(openQuote + 1, closeQuote);
    }

    // ------------------------------------------------------------------ //
    //  Object                                                              //
    // ------------------------------------------------------------------ //

    /**
     * Devuelve una representación segura ocultando el valor real de los
     * tokens para evitar fugas en logs.
     */
    @Override
    public String toString() {
        return "OAuthTokens{" +
                "accessToken="    + mask(accessToken)  +
                ", refreshToken=" + mask(refreshToken) +
                '}';
    }

    /**
     * Enmascara un token mostrando solo los primeros 8 caracteres.
     *
     * @param token token a enmascarar; puede ser {@code null}
     * @return cadena enmascarada
     */
    @NotNull
    private static String mask(@Nullable String token) {
        if (token == null) return "null";
        if (token.length() <= 8) return "***";
        return token.substring(0, 8) + "***";
    }
}
