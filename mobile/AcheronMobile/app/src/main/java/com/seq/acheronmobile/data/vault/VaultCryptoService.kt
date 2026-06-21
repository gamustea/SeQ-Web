package com.seq.acheronmobile.data.vault

import com.seq.acheron.util.CryptoUtils
import com.seq.acheronmobile.data.model.StorableCreateRequest
import com.seq.acheron.vault.User
import com.seq.acheron.vault.Vault
import com.seq.acheron.vault.VaultFactory
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategyFactory
import com.seq.acheron.vault.storables.Account
import com.seq.acheron.vault.storables.CreditCard
import com.seq.acheron.vault.storables.VaultObject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.GeneralSecurityException

data class StorableUi(
    val id: String,
    val title: String,
    val kind: String,
    val createdAt: String,
    val updatedAt: String,
    val details: Map<String, String>
)

sealed class VaultState {
    data object Locked : VaultState()
    data object NoVault : VaultState()
    data class Unlocked(
        val storables: List<StorableUi>
    ) : VaultState()
    data class Error(val message: String) : VaultState()
}

class VaultCryptoService {

    private var vault: Vault? = null
    private var vaultFactory: VaultFactory? = null

    private val _state = MutableStateFlow<VaultState>(VaultState.Locked)
    val state: StateFlow<VaultState> = _state.asStateFlow()

    private fun user(userId: String): User = User(userId, "", "", "", userId)

    fun unlockFromJson(userId: String, vaultJson: String, password: String): Boolean {
        val factory = VaultFactory(user(userId))
        vaultFactory = factory
        return try {
            val v = factory.fromJson(vaultJson, password)
            v.decryptAll()
            vault = v
            _state.value = VaultState.Unlocked(storablesToUi(v))
            true
        } catch (_: com.seq.acheron.exceptions.WrongPasswordException) {
            _state.value = VaultState.Locked
            false
        } catch (e: GeneralSecurityException) {
            _state.value = VaultState.Error("Crypto error: ${e.localizedMessage}")
            false
        } catch (e: Exception) {
            _state.value = VaultState.Error(e.localizedMessage ?: "Unknown error")
            false
        }
    }

    fun createVault(userId: String, password: String): String {
        val u = user(userId)
        val factory = VaultFactory(u)
        vaultFactory = factory

        return try {
            val salt = CryptoUtils.generateSalt()
            val strategy = VaultEncryptingStrategyFactory.create(password, salt)
            val v = Vault(strategy, u, false)
            this.vault = v
            _state.value = VaultState.Unlocked(emptyList())
            v.encryptAll()
            val json = v.toJson()
            v.decryptAll()
            json
        } catch (e: GeneralSecurityException) {
            _state.value = VaultState.Error("Crypto error: ${e.localizedMessage}")
            throw e
        }
    }

    fun exportEncryptedJson(): String {
        val v = vault ?: throw IllegalStateException("Vault not open")
        return try {
            v.encryptAll()
            val json = v.toJson()
            v.decryptAll()
            json
        } catch (e: GeneralSecurityException) {
            throw RuntimeException("Failed to export vault", e)
        }
    }

    /**
     * Crea un Account en el vault (en claro, para el estado local) y devuelve la
     * peticion de alta con sus campos ya cifrados, lista para `POST /storables`.
     */
    fun addAccount(
        title: String, username: String, domain: String, password: String
    ): StorableCreateRequest {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val acc = Account(title, username, domain, password, false)
        v.add(acc)
        val request = buildCreateRequest(acc.id, "account")
        refreshState()
        return request
    }

    /**
     * Crea un CreditCard en el vault (en claro, para el estado local) y devuelve
     * la peticion de alta con sus campos ya cifrados, lista para `POST /storables`.
     */
    fun addCreditCard(
        title: String, cardHolderName: String, cardNumber: String,
        expirationDate: String, cvv: String, postalCode: String
    ): StorableCreateRequest {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val cc = CreditCard(title, cardHolderName, cardNumber, expirationDate,
            cvv, postalCode, false)
        v.add(cc)
        val request = buildCreateRequest(cc.id, "creditcard")
        refreshState()
        return request
    }

    /**
     * Cifra el storable recien creado (sobre una copia) y arma el
     * [StorableCreateRequest] con sus campos. Las claves del JSON cifrado que
     * produce el Vault coinciden con los nombres esperados por la API.
     */
    private fun buildCreateRequest(id: String, kind: String): StorableCreateRequest {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val j = Json.parseToJsonElement(v.exportEncryptedStorable(id)).jsonObject
        fun field(name: String): String? = j[name]?.jsonPrimitive?.contentOrNull
        return if (kind == "account") {
            StorableCreateRequest(
                kind = "account",
                title = field("title"),
                internalId = id,
                createdAt = field("createdAt"),
                updatedAt = field("updatedAt"),
                username = field("username"),
                domain = field("domain"),
                password = field("password"),
            )
        } else {
            StorableCreateRequest(
                kind = "creditcard",
                title = field("title"),
                internalId = id,
                createdAt = field("createdAt"),
                updatedAt = field("updatedAt"),
                cardHolderName = field("cardHolderName"),
                cardNumber = field("cardNumber"),
                expirationDate = field("expirationDate"),
                postalCode = field("postalCode"),
                cvv = field("cvv"),
            )
        }
    }

    fun removeStorable(internalId: String): Boolean {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val storable = v.get(internalId) ?: return false
        v.remove(storable)
        refreshState()
        return true
    }

    /**
     * Aplica los cambios en claro al Account en memoria y devuelve SOLO los
     * campos modificados ya cifrados, listos para enviarse a `PATCH /storables`.
     *
     * @return mapa `campo -> valor cifrado`; vacío si no hubo cambios;
     *         `null` si el id no existe o no es un Account.
     */
    fun updateAccount(id: String, title: String?, username: String?, domain: String?, password: String?): Map<String, String>? {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val storable = v.get(id) ?: return null
        if (storable !is Account) return null

        val changed = mutableListOf<String>()
        title?.let { storable.title = it; changed += "title" }
        username?.let { storable.username = it; changed += "username" }
        domain?.let { storable.domain = it; changed += "domain" }
        password?.let { storable.password = it; changed += "password" }
        if (changed.isEmpty()) return emptyMap()

        storable.updatedAt = java.util.Date()
        val changes = encryptChangedFields(id, changed)
        refreshState()
        return changes
    }

    /**
     * Aplica los cambios en claro al CreditCard en memoria y devuelve SOLO los
     * campos modificados ya cifrados, listos para enviarse a `PATCH /storables`.
     *
     * @return mapa `campo -> valor cifrado`; vacío si no hubo cambios;
     *         `null` si el id no existe o no es un CreditCard.
     */
    fun updateCreditCard(id: String, title: String?, cardHolderName: String?, cardNumber: String?,
                         expirationDate: String?, cvv: String?, postalCode: String?): Map<String, String>? {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val storable = v.get(id) ?: return null
        if (storable !is CreditCard) return null

        val changed = mutableListOf<String>()
        title?.let { storable.title = it; changed += "title" }
        cardHolderName?.let { storable.cardHolderName = it; changed += "cardHolderName" }
        cardNumber?.let { storable.cardNumber = it; changed += "cardNumber" }
        expirationDate?.let { storable.expirationDate = it; changed += "expirationDate" }
        cvv?.let { storable.cvv = it; changed += "cvv" }
        postalCode?.let { storable.postalCode = it; changed += "postalCode" }
        if (changed.isEmpty()) return emptyMap()

        storable.updatedAt = java.util.Date()
        val changes = encryptChangedFields(id, changed)
        refreshState()
        return changes
    }

    /**
     * Cifra el storable indicado (sobre una copia, sin tocar el item vivo) y
     * extrae únicamente los campos listados. Las claves del JSON cifrado que
     * produce el Vault coinciden con los nombres de campo esperados por la API.
     */
    private fun encryptChangedFields(id: String, fields: List<String>): Map<String, String> {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val encrypted = Json.parseToJsonElement(v.exportEncryptedStorable(id)).jsonObject
        return fields.associateWith { field ->
            encrypted[field]?.jsonPrimitive?.content
                ?: throw IllegalStateException("Missing encrypted field '$field' for storable $id")
        }
    }

    fun lock() {
        vault = null
        vaultFactory = null
        _state.value = VaultState.Locked
    }

    fun isOpen(): Boolean = vault != null

    private fun refreshState() {
        val v = vault ?: return
        _state.value = VaultState.Unlocked(storablesToUi(v))
    }

    private fun storablesToUi(v: Vault): List<StorableUi> {
        return v.storables.mapNotNull { storable ->
            val vo = storable as? VaultObject ?: return@mapNotNull null
            when (storable) {
                is Account -> StorableUi(
                    id = storable.id,
                    title = storable.title,
                    kind = "account",
                    createdAt = storable.createdAt.toInstant().toString(),
                    updatedAt = storable.updatedAt.toInstant().toString(),
                    details = mapOf(
                        "username" to storable.username,
                        "domain" to storable.domain,
                        "password" to storable.password
                    )
                )
                is CreditCard -> {
                    val pan = storable.cardNumber
                    val maskedPan = if (pan != null && pan.length >= 4) "****" + pan.takeLast(4) else "****"
                    StorableUi(
                        id = storable.id,
                        title = storable.title,
                        kind = "creditcard",
                        createdAt = storable.createdAt.toInstant().toString(),
                        updatedAt = storable.updatedAt.toInstant().toString(),
                        details = mapOf(
                            "cardHolderName" to (storable.cardHolderName ?: ""),
                            "cardNumber" to maskedPan,
                            "expirationDate" to (storable.expirationDate ?: ""),
                            "postalCode" to (storable.postalCode ?: ""),
                            "cvv" to (storable.cvv ?: "")
                        )
                    )
                }
                else -> StorableUi(
                    id = vo.id,
                    title = vo.title,
                    kind = "unknown",
                    createdAt = vo.createdAt.toInstant().toString(),
                    updatedAt = vo.updatedAt.toInstant().toString(),
                    details = emptyMap()
                )
            }
        }
    }
}
