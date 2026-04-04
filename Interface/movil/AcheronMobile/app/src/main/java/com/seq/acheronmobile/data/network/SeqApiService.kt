package com.seq.acheronmobile.data.network

import com.seq.acheronmobile.data.model.LoginRequest
import com.seq.acheronmobile.data.model.TokenResponse
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.POST

interface SeqApiService {

    /**
     * POST /oauth/token
     * Soporta grant_type "password" y "refresh_token".
     * Devuelve Response<> para poder inspeccionar el código HTTP manualmente.
     */
    @POST("oauth/token")
    suspend fun getToken(
        @Body body: LoginRequest
    ): Response<TokenResponse>
}