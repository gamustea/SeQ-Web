package com.seq.acheronmobile.data.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class VaultUpsertResponse(
    val message: String,
    val vaultId: Int
)

@Serializable
data class StorableCreateRequest(
    val kind: String,
    val title: String? = null,
    @SerialName("internalId") val internalId: String? = null,
    @SerialName("createdAt") val createdAt: String? = null,
    @SerialName("updatedAt") val updatedAt: String? = null,
    val username: String? = null,
    val domain: String? = null,
    val password: String? = null,
    @SerialName("cardHolderName") val cardHolderName: String? = null,
    @SerialName("cardNumber") val cardNumber: String? = null,
    @SerialName("expirationDate") val expirationDate: String? = null,
    @SerialName("postalCode") val postalCode: String? = null,
    val cvv: String? = null,
    // SecureNote
    val content: String? = null,
    // Identity
    val fullName: String? = null,
    val email: String? = null,
    val phone: String? = null,
    val address: String? = null,
    val city: String? = null,
    val country: String? = null,
    val documentId: String? = null,
    // BankAccount
    val bankName: String? = null,
    val holder: String? = null,
    val iban: String? = null,
    val swiftBic: String? = null,
    val accountNumber: String? = null,
    // WifiNetwork (password reused from above)
    val ssid: String? = null,
    val securityType: String? = null,
    // SoftwareLicense
    val product: String? = null,
    val licenseKey: String? = null,
    val licensedTo: String? = null,
    val version: String? = null
)

@Serializable
data class StorableDeleteRequest(
    @SerialName("internalId") val internalId: String
)

@Serializable
data class StorableResponse(
    val message: String,
    val storableId: Int,
    val internalId: String,
    val vaultId: Int,
    val kind: String
)

@Serializable
data class BulkUpdateRequest(
    @SerialName("internalId") val internalId: String,
    val changes: Map<String, String>
)

@Serializable
data class BulkUpdateResponse(
    val message: String,
    val results: List<kotlinx.serialization.json.JsonObject>
)

@Serializable
data class MissingPermissions(
    @SerialName("at_least_one") val atLeastOne: List<String> = emptyList(),
    @SerialName("all_required") val allRequired: List<String> = emptyList()
)

@Serializable
data class ApiErrorResponse(
    val code: String? = null,
    val message: String? = null,
    val status: String? = null,
    val error: String? = null,
    @SerialName("error_description") val errorDescription: String? = null,
    @SerialName("missing_permissions") val missingPermissions: MissingPermissions? = null,
    @SerialName("user_message") val userMessage: String? = null
) {
    fun displayMessage(): String? {
        val missingNames = (missingPermissions?.atLeastOne.orEmpty() + missingPermissions?.allRequired.orEmpty())
            .distinct()
        if (error == "forbidden" || !missingNames.isEmpty()) {
            return if (missingNames.isEmpty()) {
                "No tienes permisos para realizar esta accion"
            } else {
                "No tienes permisos para realizar esta accion (falta: ${missingNames.joinToString(", ")})"
            }
        }
        return errorDescription ?: userMessage
    }
}
