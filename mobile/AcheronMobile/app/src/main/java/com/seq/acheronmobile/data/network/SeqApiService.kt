package com.seq.acheronmobile.data.network

import com.seq.acheronmobile.data.model.BulkUpdateRequest
import com.seq.acheronmobile.data.model.BulkUpdateResponse
import com.seq.acheronmobile.data.model.LoginRequest
import com.seq.acheronmobile.data.model.RefreshTokenRequest
import com.seq.acheronmobile.data.model.StorableCreateRequest
import com.seq.acheronmobile.data.model.StorableDeleteRequest
import com.seq.acheronmobile.data.model.StorableResponse
import com.seq.acheronmobile.data.model.TokenResponse
import com.seq.acheronmobile.data.model.VaultUpsertResponse
import kotlinx.serialization.json.JsonObject
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Query

interface SeqApiService {

    // ── OAuth ──────────────────────────────────────────────────────────

    @POST("oauth/token")
    suspend fun getToken(
        @Body body: LoginRequest
    ): Response<TokenResponse>

    @POST("oauth/token")
    suspend fun refreshToken(
        @Body body: RefreshTokenRequest
    ): Response<TokenResponse>

    // ── Acheron Vault ──────────────────────────────────────────────────

    @GET("vault")
    suspend fun getVault(
        @Query("isRecovery") isRecovery: Boolean = false
    ): Response<JsonObject>

    @POST("vault")
    suspend fun upsertVault(
        @Body body: JsonObject,
        @Query("isRecovery") isRecovery: Boolean = false
    ): Response<VaultUpsertResponse>

    // ── Acheron Storables ──────────────────────────────────────────────

    @POST("storables")
    suspend fun addStorable(
        @Body body: StorableCreateRequest
    ): Response<StorableResponse>

    @DELETE("storables")
    suspend fun deleteStorable(
        @Body body: StorableDeleteRequest
    ): Response<StorableResponse>

    @PATCH("storables")
    suspend fun bulkUpdateStorables(
        @Body body: List<BulkUpdateRequest>
    ): Response<BulkUpdateResponse>
}