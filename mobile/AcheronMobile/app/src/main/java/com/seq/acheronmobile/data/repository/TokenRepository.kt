package com.seq.acheronmobile.data.repository

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.core.content.edit
import com.seq.acheronmobile.data.model.RefreshTokenRequest
import com.seq.acheronmobile.data.network.SeqApiService
import kotlinx.coroutines.runBlocking

/**
 * Almacena y recupera los tokens OAuth de forma segura usando
 * EncryptedSharedPreferences respaldado por el Android Keystore.
 *
 * La MasterKey usa AES-256-GCM. Las claves del mapa se cifran
 * con AES-256-SIV y los valores con AES-256-GCM.
 *
 * NUNCA almacenar tokens en SharedPreferences plano, ficheros o Room
 * sin cifrado adicional.
 */
class TokenRepository(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "acheron_secure_prefs",          // nombre del fichero cifrado
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    companion object {
        private const val KEY_ACCESS_TOKEN  = "access_token"
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_EXPIRES_AT    = "expires_at"
    }

    fun saveTokens(accessToken: String, refreshToken: String?, expiresIn: Double) {
        val expiresAt = System.currentTimeMillis() + (expiresIn.toLong() * 1000L)
        prefs.edit {
            putString(KEY_ACCESS_TOKEN, accessToken)
                .putLong(KEY_EXPIRES_AT, expiresAt)
                .apply {
                    if (refreshToken != null) putString(KEY_REFRESH_TOKEN, refreshToken)
                }
        }
    }

    fun getAccessToken(): String? = prefs.getString(KEY_ACCESS_TOKEN, null)

    fun getRefreshToken(): String? = prefs.getString(KEY_REFRESH_TOKEN, null)

    fun isAccessTokenExpired(): Boolean {
        val expiresAt = prefs.getLong(KEY_EXPIRES_AT, 0L)
        // Margen de 60 s para evitar edge cases de expiración en vuelo
        return System.currentTimeMillis() >= (expiresAt - 60_000L)
    }

    fun hasValidSession(): Boolean =
        getAccessToken() != null && !isAccessTokenExpired()

    fun clearTokens() {
        prefs.edit {
            remove(KEY_ACCESS_TOKEN)
                .remove(KEY_REFRESH_TOKEN)
                .remove(KEY_EXPIRES_AT)
        }
    }

    fun refreshAccessTokenSync(apiService: SeqApiService): String? {
        val currentRefresh = getRefreshToken() ?: return null

        return try {
            val response = runBlocking {
                apiService.refreshToken(RefreshTokenRequest(refreshToken = currentRefresh))
            }
            if (response.isSuccessful) {
                val body = response.body()!!
                saveTokens(
                    accessToken = body.accessToken,
                    refreshToken = body.refreshToken ?: currentRefresh, // conservar el refresh si la API no devuelve uno nuevo
                    expiresIn = body.expiresIn
                )
                body.accessToken
            } else {
                clearTokens()
                null
            }
        } catch (e: Exception) {
            null
        }
    }
}