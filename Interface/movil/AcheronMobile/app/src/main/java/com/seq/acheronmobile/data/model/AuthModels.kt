package com.seq.acheronmobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Cuerpo del POST /oauth/token con grant_type password */
@Serializable
data class LoginRequest(
    @SerialName("grantType") val grantType: String = "password",
    @SerialName("username")  val username: String,
    @SerialName("password")  val password: String
)

/** Respuesta exitosa de /oauth/token */
@Serializable
data class TokenResponse(
    @SerialName("access_token")  val accessToken: String,
    @SerialName("token_type")    val tokenType: String,
    @SerialName("expires_in")    val expiresIn: Double,
    @SerialName("refresh_token") val refreshToken: String? = null
)

/** Respuesta de error OAuth estándar */
@Serializable
data class OAuthErrorResponse(
    @SerialName("error")             val error: String,
    @SerialName("error_description") val errorDescription: String? = null
)