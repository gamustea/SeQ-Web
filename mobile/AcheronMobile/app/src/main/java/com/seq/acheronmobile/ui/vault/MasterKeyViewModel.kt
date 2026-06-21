package com.seq.acheronmobile.ui.vault

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.seq.acheronmobile.data.repository.VaultRemoteDataSource
import com.seq.acheronmobile.data.vault.VaultState
import com.seq.acheronmobile.di.VaultServiceLocator
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

data class MasterKeyUiState(
    val masterPassword: String = "",
    val confirmPassword: String = "",
    val isLoading: Boolean = false,
    val isCreating: Boolean = false,
    val errorMessage: String? = null,
    val unlocked: Boolean = false,
    // null = aun comprobando si existe boveda; true = existe (desbloquear);
    // false = no existe (crear). probeError != null = la comprobacion fallo.
    val vaultExists: Boolean? = null,
    val probeError: String? = null
)

class MasterKeyViewModel : ViewModel() {

    private val crypto = VaultServiceLocator.cryptoService
    private val remote = VaultServiceLocator.remoteDataSource

    // Blob cifrado de la boveda obtenido durante la comprobacion; se reutiliza
    // al desbloquear para no volver a pedirlo al servidor.
    private var cachedVaultJson: JsonObject? = null

    private val _uiState = MutableStateFlow(MasterKeyUiState())
    val uiState: StateFlow<MasterKeyUiState> = _uiState.asStateFlow()

    init {
        checkVault()
    }

    /**
     * Determina por adelantado si el usuario tiene una boveda, ANTES de pedir la
     * clave maestra. Asi la UI puede llevar directamente a desbloquear (si
     * existe) o a la bienvenida/creacion (si no), en lugar de descubrirlo solo
     * tras enviar la contraseña.
     */
    fun checkVault() {
        _uiState.update { it.copy(vaultExists = null, probeError = null, errorMessage = null) }
        viewModelScope.launch {
            when (val result = remote.fetchVault()) {
                is VaultRemoteDataSource.Result.Success -> {
                    cachedVaultJson = result.data
                    _uiState.update { it.copy(vaultExists = true) }
                }
                is VaultRemoteDataSource.Result.Error -> {
                    if (result.code == 404) {
                        cachedVaultJson = null
                        _uiState.update { it.copy(vaultExists = false) }
                    } else {
                        _uiState.update { it.copy(probeError = result.message) }
                    }
                }
                is VaultRemoteDataSource.Result.NetworkError -> {
                    _uiState.update { it.copy(probeError = "Sin conexión. Comprueba tu red.") }
                }
            }
        }
    }

    fun onPasswordChange(value: String) {
        _uiState.update { it.copy(masterPassword = value, errorMessage = null) }
    }

    fun onConfirmChange(value: String) {
        _uiState.update { it.copy(confirmPassword = value, errorMessage = null) }
    }

    fun onUnlockClick() {
        val password = _uiState.value.masterPassword
        if (password.isBlank()) {
            _uiState.update { it.copy(errorMessage = "Introduce la clave maestra") }
            return
        }

        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, isCreating = false, errorMessage = null) }

            // Reutiliza el blob cacheado; si falta (raro), lo vuelve a pedir.
            val vault = cachedVaultJson ?: when (val r = remote.fetchVault()) {
                is VaultRemoteDataSource.Result.Success -> r.data.also { cachedVaultJson = it }
                is VaultRemoteDataSource.Result.Error -> {
                    if (r.code == 404) {
                        _uiState.update { it.copy(isLoading = false, vaultExists = false) }
                    } else {
                        _uiState.update { it.copy(isLoading = false, errorMessage = r.message) }
                    }
                    return@launch
                }
                is VaultRemoteDataSource.Result.NetworkError -> {
                    _uiState.update {
                        it.copy(isLoading = false, errorMessage = "Sin conexión. Comprueba tu red.")
                    }
                    return@launch
                }
            }

            crypto.unlockFromJson(VaultServiceLocator.username, vault.toString(), password)
            when (val state = crypto.state.value) {
                is VaultState.Unlocked -> {
                    _uiState.update { it.copy(isLoading = false, unlocked = true) }
                }
                is VaultState.Locked -> {
                    _uiState.update {
                        it.copy(isLoading = false, errorMessage = "Clave maestra incorrecta")
                    }
                }
                is VaultState.Error -> {
                    _uiState.update {
                        it.copy(isLoading = false, errorMessage = "Error: ${state.message}")
                    }
                }
                else -> {
                    _uiState.update {
                        it.copy(isLoading = false, errorMessage = "Error al abrir la bóveda")
                    }
                }
            }
        }
    }

    fun onCreateVaultClick() {
        val state = _uiState.value
        val password = state.masterPassword
        if (password.length < 8) {
            _uiState.update { it.copy(errorMessage = "La clave debe tener al menos 8 caracteres") }
            return
        }
        if (password != state.confirmPassword) {
            _uiState.update { it.copy(errorMessage = "Las claves no coinciden") }
            return
        }

        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, isCreating = true, errorMessage = null) }
            try {
                val vaultJson = crypto.createVault(VaultServiceLocator.username, password)
                val json = Json.parseToJsonElement(vaultJson).jsonObject

                when (val result = remote.pushVault(json)) {
                    is VaultRemoteDataSource.Result.Success -> {
                        cachedVaultJson = json
                        _uiState.update { it.copy(isLoading = false, unlocked = true) }
                    }
                    is VaultRemoteDataSource.Result.Error -> {
                        _uiState.update {
                            it.copy(isLoading = false, errorMessage = "Error al guardar: ${result.message}")
                        }
                    }
                    is VaultRemoteDataSource.Result.NetworkError -> {
                        _uiState.update {
                            it.copy(isLoading = false, errorMessage = "Sin conexión. Comprueba tu red.")
                        }
                    }
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(isLoading = false, errorMessage = "Error al crear la bóveda: ${e.localizedMessage}")
                }
            }
        }
    }

    fun onNavigatedToVault() {
        _uiState.update { it.copy(unlocked = false) }
    }
}
