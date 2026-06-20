package com.seq.acheronmobile.ui.vault

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.seq.acheronmobile.data.model.BulkUpdateRequest
import com.seq.acheronmobile.data.model.StorableCreateRequest
import com.seq.acheronmobile.data.repository.VaultRemoteDataSource
import com.seq.acheronmobile.data.vault.StorableUi
import com.seq.acheronmobile.data.vault.VaultCryptoService
import com.seq.acheronmobile.data.vault.VaultState
import com.seq.acheronmobile.di.VaultServiceLocator
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

data class VaultUiState(
    val storables: List<StorableUi> = emptyList(),
    val isLoading: Boolean = false,
    val syncing: Boolean = false,
    val errorMessage: String? = null,
    val locked: Boolean = false
)

class VaultViewModel : ViewModel() {

    private val crypto = VaultServiceLocator.cryptoService
    private val remote = VaultServiceLocator.remoteDataSource

    private val _uiState = MutableStateFlow(VaultUiState())
    val uiState: StateFlow<VaultUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            crypto.state.collectLatest { state ->
                when (state) {
                    is VaultState.Unlocked -> {
                        _uiState.update {
                            it.copy(storables = state.storables, locked = false)
                        }
                    }
                    is VaultState.Locked -> {
                        _uiState.update { it.copy(locked = true, storables = emptyList()) }
                    }
                    is VaultState.Error -> {
                        _uiState.update { it.copy(errorMessage = state.message) }
                    }
                    VaultState.NoVault -> {}
                }
            }
        }
    }

    fun syncToRemote() {
        viewModelScope.launch {
            _uiState.update { it.copy(syncing = true, errorMessage = null) }
            try {
                val vaultJson = crypto.exportEncryptedJson()
                val json = Json.parseToJsonElement(vaultJson).jsonObject
                when (val result = remote.pushVault(json)) {
                    is VaultRemoteDataSource.Result.Success -> {
                        _uiState.update { it.copy(syncing = false) }
                    }
                    is VaultRemoteDataSource.Result.Error -> {
                        _uiState.update {
                            it.copy(syncing = false, errorMessage = result.message)
                        }
                    }
                    is VaultRemoteDataSource.Result.NetworkError -> {
                        _uiState.update {
                            it.copy(syncing = false,
                                errorMessage = "Sin conexión")
                        }
                    }
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(syncing = false,
                        errorMessage = e.localizedMessage ?: "Error")
                }
            }
        }
    }

    /**
     * Cifra y sube el vault completo tras una mutacion local. Devuelve `false`
     * y deja el motivo en `errorMessage` si el push al servidor falla, en vez
     * de ignorarlo silenciosamente.
     */
    private suspend fun pushMutation(): Boolean {
        return try {
            val encryptedJson = crypto.exportEncryptedJson()
            val json = Json.parseToJsonElement(encryptedJson).jsonObject
            when (val result = remote.pushVault(json)) {
                is VaultRemoteDataSource.Result.Success -> {
                    _uiState.update { it.copy(isLoading = false) }
                    true
                }
                is VaultRemoteDataSource.Result.Error -> {
                    _uiState.update {
                        it.copy(isLoading = false, errorMessage = result.message)
                    }
                    false
                }
                is VaultRemoteDataSource.Result.NetworkError -> {
                    _uiState.update {
                        it.copy(isLoading = false, errorMessage = "Sin conexión")
                    }
                    false
                }
            }
        } catch (e: Exception) {
            _uiState.update {
                it.copy(isLoading = false, errorMessage = e.localizedMessage ?: "Error")
            }
            false
        }
    }

    suspend fun addAccount(title: String, username: String, domain: String, password: String): Boolean {
        _uiState.update { it.copy(isLoading = true, errorMessage = null) }
        return try {
            crypto.addAccount(title, username, domain, password)
            pushMutation()
        } catch (e: Exception) {
            _uiState.update {
                it.copy(isLoading = false, errorMessage = e.localizedMessage ?: "Error")
            }
            false
        }
    }

    suspend fun addCreditCard(title: String, holder: String, number: String,
                      expiry: String, cvv: String, postal: String): Boolean {
        _uiState.update { it.copy(isLoading = true, errorMessage = null) }
        return try {
            crypto.addCreditCard(title, holder, number, expiry, cvv, postal)
            pushMutation()
        } catch (e: Exception) {
            _uiState.update {
                it.copy(isLoading = false, errorMessage = e.localizedMessage ?: "Error")
            }
            false
        }
    }

    suspend fun deleteStorable(internalId: String): Boolean {
        _uiState.update { it.copy(isLoading = true, errorMessage = null) }
        return try {
            crypto.removeStorable(internalId)
            pushMutation()
        } catch (e: Exception) {
            _uiState.update {
                it.copy(isLoading = false, errorMessage = e.localizedMessage ?: "Error")
            }
            false
        }
    }

    suspend fun updateAccount(id: String, title: String?, username: String?, domain: String?, password: String?): Boolean {
        _uiState.update { it.copy(isLoading = true, errorMessage = null) }
        return try {
            crypto.updateAccount(id, title, username, domain, password)
            pushMutation()
        } catch (e: Exception) {
            _uiState.update {
                it.copy(isLoading = false, errorMessage = e.localizedMessage ?: "Error")
            }
            false
        }
    }

    suspend fun updateCreditCard(id: String, title: String?, holder: String?, number: String?,
                         expiry: String?, cvv: String?, postal: String?): Boolean {
        _uiState.update { it.copy(isLoading = true, errorMessage = null) }
        return try {
            crypto.updateCreditCard(id, title, holder, number, expiry, cvv, postal)
            pushMutation()
        } catch (e: Exception) {
            _uiState.update {
                it.copy(isLoading = false, errorMessage = e.localizedMessage ?: "Error")
            }
            false
        }
    }

    fun lockVault() {
        crypto.lock()
    }

    fun clearError() {
        _uiState.update { it.copy(errorMessage = null) }
    }
}
