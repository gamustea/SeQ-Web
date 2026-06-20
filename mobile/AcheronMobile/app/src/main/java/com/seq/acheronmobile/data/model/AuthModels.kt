package com.seq.acheronmobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class LoginRequest(
    @SerialName("grantType") val grantType: String = "password",
    @SerialName("username")  val username: String,
    @SerialName("password")  val password: String
)

@Serializable
data class TokenResponse(
    @SerialName("access_token")  val accessToken: String,
    @SerialName("token_type")    val tokenType: String,
    @SerialName("expires_in")    val expiresIn: Double,
    @SerialName("refresh_token") val refreshToken: String? = null
)

@Serializable
data class OAuthErrorResponse(
    @SerialName("error")             val error: String,
    @SerialName("error_description") val errorDescription: String? = null
)

@Serializable
data class RefreshTokenRequest(
    @SerialName("grantType")      val grantType: String = "refresh_token",
    @SerialName("refresh_token")  val refreshToken: String
)