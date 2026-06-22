package com.seq.acheronmobile.data.vault

import com.seq.acheron.util.CryptoUtils
import com.seq.acheronmobile.data.model.StorableCreateRequest
import com.seq.acheron.vault.User
import com.seq.acheron.vault.Vault
import com.seq.acheron.vault.VaultFactory
import com.seq.acheron.vault.secrets.symmetric.VaultEncryptingStrategyFactory
import com.seq.acheron.vault.storables.Account
import com.seq.acheron.vault.storables.BankAccount
import com.seq.acheron.vault.storables.CreditCard
import com.seq.acheron.vault.storables.Identity
import com.seq.acheron.vault.storables.SecureNote
import com.seq.acheron.vault.storables.SoftwareLicense
import com.seq.acheron.vault.storables.WifiNetwork
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
     * Crea un storable del [kind] indicado en el vault (en claro, para el estado
     * local) a partir de un mapa `campo -> valor`, y devuelve la petición de alta
     * con sus campos ya cifrados, lista para `POST /storables`.
     */
    fun addStorable(
        kind: String, title: String, fields: Map<String, String>
    ): StorableCreateRequest {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val storable = createStorable(kind, title, fields)
        v.add(storable)
        val request = buildCreateRequest(storable.id, kind)
        refreshState()
        return request
    }

    /**
     * Construye el [VaultObject] concreto correspondiente al [kind] a partir de
     * un mapa de campos. Es el único punto del lado Kotlin que conoce las firmas
     * posicionales de los constructores del core.
     */
    private fun createStorable(kind: String, title: String, f: Map<String, String>): VaultObject {
        fun g(key: String): String = f[key] ?: ""
        return when (kind) {
            "account" -> Account(title, g("username"), g("domain"), g("password"), false)
            "creditcard" -> CreditCard(
                title, g("cardHolderName"), g("cardNumber"),
                g("expirationDate"), g("cvv"), g("postalCode"), false
            )
            "securenote" -> SecureNote(title, g("content"), false)
            "identity" -> Identity(
                title, g("fullName"), g("email"), g("phone"),
                g("address"), g("city"), g("country"), g("documentId"), false
            )
            "bankaccount" -> BankAccount(
                title, g("bankName"), g("holder"), g("iban"),
                g("swiftBic"), g("accountNumber"), false
            )
            "wifi" -> WifiNetwork(title, g("ssid"), g("password"), g("securityType"), false)
            "license" -> SoftwareLicense(
                title, g("product"), g("licenseKey"), g("licensedTo"), g("version"), false
            )
            else -> throw IllegalArgumentException("Unknown storable kind: $kind")
        }
    }

    /**
     * Cifra el storable recien creado (sobre una copia) y arma el
     * [StorableCreateRequest] con sus campos. Las claves del JSON cifrado que
     * produce el Vault coinciden con los nombres esperados por la API; solo los
     * campos presentes en este tipo viajan con valor (el resto quedan nulos).
     */
    private fun buildCreateRequest(id: String, kind: String): StorableCreateRequest {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val j = Json.parseToJsonElement(v.exportEncryptedStorable(id)).jsonObject
        fun field(name: String): String? = j[name]?.jsonPrimitive?.contentOrNull
        return StorableCreateRequest(
            kind = kind,
            title = field("title"),
            internalId = id,
            createdAt = field("createdAt"),
            updatedAt = field("updatedAt"),
            username = field("username"),
            domain = field("domain"),
            password = field("password"),
            cardHolderName = field("cardHolderName"),
            cardNumber = field("cardNumber"),
            expirationDate = field("expirationDate"),
            postalCode = field("postalCode"),
            cvv = field("cvv"),
            content = field("content"),
            fullName = field("fullName"),
            email = field("email"),
            phone = field("phone"),
            address = field("address"),
            city = field("city"),
            country = field("country"),
            documentId = field("documentId"),
            bankName = field("bankName"),
            holder = field("holder"),
            iban = field("iban"),
            swiftBic = field("swiftBic"),
            accountNumber = field("accountNumber"),
            ssid = field("ssid"),
            securityType = field("securityType"),
            product = field("product"),
            licenseKey = field("licenseKey"),
            licensedTo = field("licensedTo"),
            version = field("version"),
        )
    }

    fun removeStorable(internalId: String): Boolean {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val storable = v.get(internalId) ?: return false
        v.remove(storable)
        refreshState()
        return true
    }

    /**
     * Aplica al storable en memoria (en claro) los cambios indicados y devuelve
     * SOLO los campos modificados ya cifrados, listos para `PATCH /storables`.
     * Cada entrada de [fields] con valor no nulo se considera un cambio; las
     * nulas se ignoran (no se tocan).
     *
     * @return mapa `campo -> valor cifrado`; vacío si no hubo cambios;
     *         `null` si el id no existe.
     */
    fun updateStorable(id: String, title: String?, fields: Map<String, String?>): Map<String, String>? {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val storable = v.get(id) as? VaultObject ?: return null

        val changed = mutableListOf<String>()
        title?.let { storable.title = it; changed += "title" }
        fields.forEach { (key, value) ->
            if (value != null && applyField(storable, key, value)) changed += key
        }
        if (changed.isEmpty()) return emptyMap()

        storable.updatedAt = java.util.Date()
        val changes = encryptChangedFields(id, changed)
        refreshState()
        return changes
    }

    /**
     * Asigna [value] al campo [key] del storable, usando los setters tipados del
     * core. Devuelve `true` si el campo pertenece al tipo, `false` en caso
     * contrario (campo desconocido para ese tipo).
     */
    private fun applyField(s: VaultObject, key: String, value: String): Boolean = when (s) {
        is Account -> when (key) {
            "username" -> { s.username = value; true }
            "domain" -> { s.domain = value; true }
            "password" -> { s.password = value; true }
            else -> false
        }
        is CreditCard -> when (key) {
            "cardHolderName" -> { s.cardHolderName = value; true }
            "cardNumber" -> { s.cardNumber = value; true }
            "expirationDate" -> { s.expirationDate = value; true }
            "cvv" -> { s.cvv = value; true }
            "postalCode" -> { s.postalCode = value; true }
            else -> false
        }
        is SecureNote -> if (key == "content") { s.content = value; true } else false
        is Identity -> when (key) {
            "fullName" -> { s.fullName = value; true }
            "email" -> { s.email = value; true }
            "phone" -> { s.phone = value; true }
            "address" -> { s.address = value; true }
            "city" -> { s.city = value; true }
            "country" -> { s.country = value; true }
            "documentId" -> { s.documentId = value; true }
            else -> false
        }
        is BankAccount -> when (key) {
            "bankName" -> { s.bankName = value; true }
            "holder" -> { s.holder = value; true }
            "iban" -> { s.iban = value; true }
            "swiftBic" -> { s.swiftBic = value; true }
            "accountNumber" -> { s.accountNumber = value; true }
            else -> false
        }
        is WifiNetwork -> when (key) {
            "ssid" -> { s.ssid = value; true }
            "password" -> { s.password = value; true }
            "securityType" -> { s.securityType = value; true }
            else -> false
        }
        is SoftwareLicense -> when (key) {
            "product" -> { s.product = value; true }
            "licenseKey" -> { s.licenseKey = value; true }
            "licensedTo" -> { s.licensedTo = value; true }
            "version" -> { s.version = value; true }
            else -> false
        }
        else -> false
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
            StorableUi(
                id = vo.id,
                title = vo.title,
                kind = kindOf(vo),
                createdAt = vo.createdAt.toInstant().toString(),
                updatedAt = vo.updatedAt.toInstant().toString(),
                details = detailsOf(vo)
            )
        }
    }

    /** Identificador de tipo expuesto a la UI/API para cada subclase del core. */
    private fun kindOf(vo: VaultObject): String = when (vo) {
        is Account -> "account"
        is CreditCard -> "creditcard"
        is SecureNote -> "securenote"
        is Identity -> "identity"
        is BankAccount -> "bankaccount"
        is WifiNetwork -> "wifi"
        is SoftwareLicense -> "license"
        else -> "unknown"
    }

    /**
     * Mapa ordenado `campo -> valor en claro` para mostrar en la UI. Se exponen
     * los valores reales descifrados salvo el PAN de la tarjeta, que se enmascara
     * a sus últimos 4 dígitos y nunca se revela íntegro.
     */
    private fun detailsOf(vo: VaultObject): Map<String, String> = when (vo) {
        is Account -> linkedMapOf(
            "username" to vo.username.orEmpty(),
            "domain" to vo.domain.orEmpty(),
            "password" to vo.password.orEmpty()
        )
        is CreditCard -> linkedMapOf(
            "cardHolderName" to vo.cardHolderName.orEmpty(),
            "cardNumber" to maskPan(vo.cardNumber),
            "expirationDate" to vo.expirationDate.orEmpty(),
            "cvv" to vo.cvv.orEmpty(),
            "postalCode" to vo.postalCode.orEmpty()
        )
        is SecureNote -> linkedMapOf("content" to vo.content.orEmpty())
        is Identity -> linkedMapOf(
            "fullName" to vo.fullName.orEmpty(),
            "email" to vo.email.orEmpty(),
            "phone" to vo.phone.orEmpty(),
            "address" to vo.address.orEmpty(),
            "city" to vo.city.orEmpty(),
            "country" to vo.country.orEmpty(),
            "documentId" to vo.documentId.orEmpty()
        )
        is BankAccount -> linkedMapOf(
            "bankName" to vo.bankName.orEmpty(),
            "holder" to vo.holder.orEmpty(),
            "iban" to vo.iban.orEmpty(),
            "swiftBic" to vo.swiftBic.orEmpty(),
            "accountNumber" to vo.accountNumber.orEmpty()
        )
        is WifiNetwork -> linkedMapOf(
            "ssid" to vo.ssid.orEmpty(),
            "password" to vo.password.orEmpty(),
            "securityType" to vo.securityType.orEmpty()
        )
        is SoftwareLicense -> linkedMapOf(
            "product" to vo.product.orEmpty(),
            "licenseKey" to vo.licenseKey.orEmpty(),
            "licensedTo" to vo.licensedTo.orEmpty(),
            "version" to vo.version.orEmpty()
        )
        else -> emptyMap()
    }

    private fun maskPan(pan: String?): String =
        if (pan != null && pan.length >= 4) "****" + pan.takeLast(4) else "****"
}
