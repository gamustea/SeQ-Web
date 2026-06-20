package com.seq.acheronmobile.data.vault

import com.seq.acheron.util.CryptoUtils
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
            vault = factory.fromJson(vaultJson, password)
            _state.value = VaultState.Unlocked(storablesToUi(vault!!))
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

    fun addAccount(
        title: String, username: String, domain: String, password: String
    ): String {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val acc = Account(title, username, domain, password, false)
        v.add(acc)
        refreshState()
        return acc.id
    }

    fun addCreditCard(
        title: String, cardHolderName: String, cardNumber: String,
        expirationDate: String, cvv: String, postalCode: String
    ): String {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val cc = CreditCard(title, cardHolderName, cardNumber, expirationDate,
            cvv, postalCode, false)
        v.add(cc)
        refreshState()
        return cc.id
    }

    fun removeStorable(internalId: String): Boolean {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val storable = v.get(internalId) ?: return false
        v.remove(storable)
        refreshState()
        return true
    }

    fun updateAccount(id: String, title: String?, username: String?, domain: String?, password: String?): Boolean {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val storable = v.get(id) ?: return false
        if (storable !is Account) return false
        title?.let { storable.title = it }
        username?.let { storable.username = it }
        domain?.let { storable.domain = it }
        password?.let { storable.password = it }
        storable.updatedAt = java.util.Date()
        refreshState()
        return true
    }

    fun updateCreditCard(id: String, title: String?, cardHolderName: String?, cardNumber: String?,
                         expirationDate: String?, cvv: String?, postalCode: String?): Boolean {
        val v = vault ?: throw IllegalStateException("Vault not open")
        val storable = v.get(id) ?: return false
        if (storable !is CreditCard) return false
        title?.let { storable.title = it }
        cardHolderName?.let { storable.cardHolderName = it }
        cardNumber?.let { storable.cardNumber = it }
        expirationDate?.let { storable.expirationDate = it }
        cvv?.let { storable.cvv = it }
        postalCode?.let { storable.postalCode = it }
        storable.updatedAt = java.util.Date()
        refreshState()
        return true
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
                        "password" to "***"
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
                            "cvv" to "***"
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
