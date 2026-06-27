package com.seq.acheronmobile.ui.vault

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.seq.acheronmobile.data.model.BulkUpdateRequest
import com.seq.acheronmobile.data.model.StorableResponse
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
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

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
     * Mapea el resultado de un alta/baja granular (`POST`/`DELETE /storables`)
     * a un booleano, dejando el motivo en `errorMessage` si falla.
     */
    private fun pushStorableResult(result: VaultRemoteDataSource.Result<StorableResponse>): Boolean {
        return when (result) {
            is VaultRemoteDataSource.Result.Success -> {
                _uiState.update { it.copy(isLoading = false) }
                true
            }
            is VaultRemoteDataSource.Result.Error -> {
                _uiState.update { it.copy(isLoading = false, errorMessage = result.message) }
                false
            }
            is VaultRemoteDataSource.Result.NetworkError -> {
                _uiState.update { it.copy(isLoading = false, errorMessage = "Sin conexión") }
                false
            }
        }
    }

    /**
     * Alta genérica de un storable de cualquier [kind] a partir de un mapa
     * `campo -> valor` (los nombres de campo provienen del [StorableTypeSpec]).
     */
    suspend fun addStorable(kind: String, title: String, fields: Map<String, String>): Boolean {
        _uiState.update { it.copy(isLoading = true, errorMessage = null) }
        return try {
            val request = crypto.addStorable(kind, title, fields)
            pushStorableResult(remote.addStorable(request))
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
            if (!crypto.removeStorable(internalId)) {
                _uiState.update {
                    it.copy(isLoading = false, errorMessage = "Elemento no encontrado")
                }
                return false
            }
            pushStorableResult(remote.deleteStorable(internalId))
        } catch (e: Exception) {
            _uiState.update {
                it.copy(isLoading = false, errorMessage = e.localizedMessage ?: "Error")
            }
            false
        }
    }

    /**
     * Actualización genérica de un storable: [fields] contiene `campo -> valor`
     * para los campos a cambiar (valor `null` = sin cambios).
     */
    suspend fun updateStorable(id: String, title: String?, fields: Map<String, String?>): Boolean {
        _uiState.update { it.copy(isLoading = true, errorMessage = null) }
        return try {
            val changes = crypto.updateStorable(id, title, fields)
            pushStorableUpdate(id, changes)
        } catch (e: Exception) {
            _uiState.update {
                it.copy(isLoading = false, errorMessage = e.localizedMessage ?: "Error")
            }
            false
        }
    }

    /**
     * Envia un cambio puntual de un storable via `PATCH /storables` (solo los
     * campos modificados, ya cifrados) en lugar de reescribir todo el vault.
     *
     * @param changes mapa de campos cifrados devuelto por el crypto service;
     *                `null` si el storable no existe, vacio si no hubo cambios.
     */
    private suspend fun pushStorableUpdate(id: String, changes: Map<String, String>?): Boolean {
        if (changes == null) {
            _uiState.update { it.copy(isLoading = false, errorMessage = "Elemento no encontrado") }
            return false
        }
        if (changes.isEmpty()) {
            _uiState.update { it.copy(isLoading = false) }
            return true
        }
        return when (val result = remote.bulkUpdate(listOf(BulkUpdateRequest(id, changes)))) {
            is VaultRemoteDataSource.Result.Success -> {
                val status = result.data.results.firstOrNull()
                    ?.get("status")?.jsonPrimitive?.contentOrNull
                if (status == "updated") {
                    _uiState.update { it.copy(isLoading = false) }
                    true
                } else {
                    _uiState.update {
                        it.copy(isLoading = false,
                            errorMessage = "No se pudo actualizar (${status ?: "desconocido"})")
                    }
                    false
                }
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
    }

    /**
     * Rota la contraseña maestra: re-cifra la clave de la bóveda con la nueva
     * contraseña (los storables no se tocan) y refresca los metadatos en el
     * servidor vía `PATCH /vault`. Tras intentarlo, bloquea la bóveda para que
     * el usuario la vuelva a abrir con la contraseña correspondiente (la nueva
     * si tuvo éxito; la antigua si falló la persistencia).
     *
     * @return `true` si el cambio se aplicó y persistió correctamente.
     */
    suspend fun changeMasterPassword(oldPassword: String, newPassword: String): Boolean {
        _uiState.update { it.copy(syncing = true, errorMessage = null) }

        val metadata = try {
            crypto.changeMasterPassword(oldPassword, newPassword)
        } catch (_: com.seq.acheron.exceptions.WrongPasswordException) {
            // Se lanza antes de mutar el vault: el usuario puede reintentar.
            _uiState.update { it.copy(syncing = false, errorMessage = "Contraseña actual incorrecta") }
            return false
        } catch (e: Exception) {
            _uiState.update {
                it.copy(syncing = false, errorMessage = e.localizedMessage ?: "Error al cambiar la contraseña")
            }
            return false
        }

        return when (val result = remote.changeVaultPassword(metadata)) {
            is VaultRemoteDataSource.Result.Success -> {
                _uiState.update { it.copy(syncing = false) }
                crypto.lock() // re-desbloqueo con la nueva contraseña
                true
            }
            is VaultRemoteDataSource.Result.Error -> {
                // El vault en memoria ya está rekeyado pero el server no: bloquea
                // para descartar el estado divergente.
                _uiState.update { it.copy(syncing = false, errorMessage = result.message) }
                crypto.lock()
                false
            }
            is VaultRemoteDataSource.Result.NetworkError -> {
                _uiState.update { it.copy(syncing = false, errorMessage = "Sin conexión") }
                crypto.lock()
                false
            }
        }
    }

    fun lockVault() {
        crypto.lock()
    }

    fun clearError() {
        _uiState.update { it.copy(errorMessage = null) }
    }
}
