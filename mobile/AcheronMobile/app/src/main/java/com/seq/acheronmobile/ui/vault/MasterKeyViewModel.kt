package com.seq.acheronmobile.ui.vault

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.seq.acheronmobile.data.repository.VaultRemoteDataSource
import com.seq.acheronmobile.data.vault.VaultCryptoService
import com.seq.acheronmobile.data.vault.VaultState
import com.seq.acheronmobile.di.VaultServiceLocator
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

data class MasterKeyUiState(
    val masterPassword: String = "",
    val isLoading: Boolean = false,
    val isCreating: Boolean = false,
    val errorMessage: String? = null,
    val unlocked: Boolean = false,
    val noVaultFound: Boolean = false
)

class MasterKeyViewModel : ViewModel() {

    private val crypto = VaultServiceLocator.cryptoService
    private val remote = VaultServiceLocator.remoteDataSource

    private val _uiState = MutableStateFlow(MasterKeyUiState())
    val uiState: StateFlow<MasterKeyUiState> = _uiState.asStateFlow()

    fun onPasswordChange(value: String) {
        _uiState.update { it.copy(masterPassword = value, errorMessage = null) }
    }

    fun onUnlockClick() {
        val password = _uiState.value.masterPassword
        if (password.isBlank()) {
            _uiState.update { it.copy(errorMessage = "Introduce la clave maestra") }
            return
        }

        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }

            when (val result = remote.fetchVault()) {
                is VaultRemoteDataSource.Result.Success -> {
                    val vaultJson = Json.encodeToJsonElement(result.data)
                    val jsonString = vaultJson.toString()
                    val ok = crypto.unlockFromJson(
                        VaultServiceLocator.username,
                        jsonString,
                        password
                    )
                    when (val state = crypto.state.value) {
                        is VaultState.Unlocked -> {
                            _uiState.update {
                                it.copy(isLoading = false, unlocked = true, noVaultFound = false)
                            }
                        }
                        is VaultState.Locked -> {
                            _uiState.update {
                                it.copy(isLoading = false, errorMessage = "Clave maestra incorrecta")
                            }
                        }
                        is VaultState.Error -> {
                            _uiState.update {
                                it.copy(isLoading = false,
                                    errorMessage = "Error: ${state.message}")
                            }
                        }
                        else -> {
                            _uiState.update {
                                it.copy(isLoading = false, errorMessage = "Error al abrir el vault")
                            }
                        }
                    }
                }
                is VaultRemoteDataSource.Result.Error -> {
                    if (result.code == 404) {
                        _uiState.update {
                            it.copy(isLoading = false, noVaultFound = true)
                        }
                    } else {
                        _uiState.update {
                            it.copy(isLoading = false, errorMessage = result.message)
                        }
                    }
                }
                is VaultRemoteDataSource.Result.NetworkError -> {
                    _uiState.update {
                        it.copy(isLoading = false,
                            errorMessage = "Sin conexion. Comprueba tu red.")
                    }
                }
            }
        }
    }

    fun onCreateVaultClick() {
        val password = _uiState.value.masterPassword
        if (password.length < 8) {
            _uiState.update { it.copy(errorMessage = "La clave debe tener al menos 8 caracteres") }
            return
        }

        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, isCreating = true, errorMessage = null) }

            try {
                val vaultJson = crypto.createVault(VaultServiceLocator.username, password)
                val json = Json.parseToJsonElement(vaultJson).jsonObject

                when (val result = remote.pushVault(json)) {
                    is VaultRemoteDataSource.Result.Success -> {
                        _uiState.update {
                            it.copy(isLoading = false, unlocked = true)
                        }
                    }
                    is VaultRemoteDataSource.Result.Error -> {
                        _uiState.update {
                            it.copy(isLoading = false,
                                errorMessage = "Error al guardar: ${result.message}")
                        }
                    }
                    is VaultRemoteDataSource.Result.NetworkError -> {
                        _uiState.update {
                            it.copy(isLoading = false,
                                errorMessage = "Sin conexion. Comprueba tu red.")
                        }
                    }
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(isLoading = false,
                        errorMessage = "Error al crear vault: ${e.localizedMessage}")
                }
            }
        }
    }

    fun onNavigatedToVault() {
        _uiState.update { it.copy(unlocked = false) }
    }
}
