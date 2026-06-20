package com.seq.acheronmobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class VaultUpsertResponse(
    val message: String,
    val vaultId: Int,
    val isRecovery: Boolean
)

@Serializable
data class StorableCreateRequest(
    val kind: String,
    val title: String? = null,
    @SerialName("internalId") val internalId: String? = null,
    @SerialName("isRecovery") val isRecovery: Boolean = false,
    @SerialName("createdAt") val createdAt: String? = null,
    @SerialName("updatedAt") val updatedAt: String? = null,
    val username: String? = null,
    val domain: String? = null,
    val password: String? = null,
    @SerialName("cardHolderName") val cardHolderName: String? = null,
    @SerialName("cardNumber") val cardNumber: String? = null,
    @SerialName("expirationDate") val expirationDate: String? = null,
    @SerialName("postalCode") val postalCode: String? = null,
    val cvv: String? = null
)

@Serializable
data class StorableDeleteRequest(
    @SerialName("internalId") val internalId: String,
    @SerialName("isRecovery") val isRecovery: Boolean = false
)

@Serializable
data class StorableResponse(
    val message: String,
    val storableId: Int,
    val internalId: String,
    val vaultId: Int,
    val isRecovery: Boolean,
    val kind: String
)

@Serializable
data class BulkUpdateRequest(
    @SerialName("internalId") val internalId: String,
    @SerialName("isRecovery") val isRecovery: Boolean = false,
    val changes: Map<String, String>
)

@Serializable
data class BulkUpdateResponse(
    val message: String,
    val results: List<kotlinx.serialization.json.JsonObject>
)

@Serializable
data class ApiErrorResponse(
    val code: String? = null,
    val message: String? = null,
    val status: String? = null,
    @SerialName("user_message") val userMessage: String? = null
)
