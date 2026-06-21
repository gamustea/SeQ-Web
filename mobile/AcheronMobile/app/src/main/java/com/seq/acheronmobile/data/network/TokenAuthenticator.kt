package com.seq.acheronmobile.data.network

import com.seq.acheronmobile.data.repository.TokenRepository
import okhttp3.Authenticator
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route

class TokenAuthenticator(
    private val tokenRepository: TokenRepository
) : Authenticator {

    // Se asigna desde NetworkModule justo después de crear Retrofit
    lateinit var apiService: SeqApiService

    override fun authenticate(route: Route?, response: Response): Request? {

        if (response.request.header("X-Retry-After-Refresh") != null) {
            tokenRepository.clearTokens()
            return null
        }

        synchronized(this) {
            val existingToken = tokenRepository.getAccessToken()
            val requestToken  = response.request.header("Authorization")
                ?.removePrefix("Bearer ")

            if (existingToken != null && existingToken != requestToken) {
                return response.request.newBuilder()
                    .header("Authorization", "Bearer $existingToken")
                    .header("X-Retry-After-Refresh", "true")
                    .build()
            }

            val newToken = tokenRepository.refreshAccessTokenSync(apiService)
                ?: return null

            return response.request.newBuilder()
                .header("Authorization", "Bearer $newToken")
                .header("X-Retry-After-Refresh", "true")
                .build()
        }
    }
}