package com.seq.acheronmobile.data.repository

import com.seq.acheronmobile.data.model.LoginRequest
import com.seq.acheronmobile.data.network.NetworkModule
import kotlinx.serialization.json.Json

/**
 * Repositorio de autenticación.
 * Coordina la llamada a la API con el almacenamiento seguro de tokens.
 */
class AuthRepository(
    private val tokenRepository: TokenRepository
) {
    private val api = NetworkModule.seqApiService

    sealed class AuthResult {
        data object Success       : AuthResult()
        data object SessionExpired : AuthResult()   // ← NUEVO
        data class Error(val message: String) : AuthResult()
        data object NetworkError  : AuthResult()
    }

    /**
     * Realiza el login con credenciales (password grant).
     * Si tiene éxito, persiste los tokens de forma cifrada.
     */
    suspend fun login(username: String, password: String): AuthResult {
        return try {
            val response = api.getToken(LoginRequest(username = username, password = password))

            if (response.isSuccessful) {
                val body = response.body()!!
                tokenRepository.saveTokens(
                    accessToken = body.accessToken,
                    refreshToken = body.refreshToken,
                    expiresIn = body.expiresIn
                )
                AuthResult.Success
            } else {
                // Intentar parsear el error OAuth estándar del cuerpo
                val errorBody = response.errorBody()?.string()
                val description = try {
                    Json.decodeFromString<com.seq.acheronmobile.data.model.OAuthErrorResponse>(
                        errorBody ?: ""
                    ).errorDescription ?: "Credenciales incorrectas"
                } catch (_: Exception) {
                    when (response.code()) {
                        401  -> "Usuario o contraseña incorrectos"
                        429  -> "Demasiados intentos. Espera un momento."
                        else -> "Error ${response.code()}"
                    }
                }
                AuthResult.Error(description)
            }
        } catch (e: java.io.IOException) {
            AuthResult.NetworkError
        } catch (e: Exception) {
            AuthResult.Error("Error inesperado: ${e.localizedMessage}")
        }
    }
}