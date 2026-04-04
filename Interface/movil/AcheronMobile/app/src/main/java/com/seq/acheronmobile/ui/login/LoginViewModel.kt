package com.seq.acheronmobile.ui.login

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.seq.acheronmobile.data.repository.AuthRepository
import com.seq.acheronmobile.data.repository.TokenRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class LoginUiState(
    val username: String      = "",
    val password: String      = "",
    val isLoading: Boolean    = false,
    val errorMessage: String? = null,
    val loginSuccess: Boolean = false
)

class LoginViewModel(
    private val authRepository: AuthRepository,
    private val tokenRepository: TokenRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState())
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()
    val hasActiveSession: Boolean
        get() = tokenRepository.hasValidSession()


    fun onUsernameChange(value: String) {
        _uiState.update { it.copy(username = value, errorMessage = null) }
    }

    fun onPasswordChange(value: String) {
        _uiState.update { it.copy(password = value, errorMessage = null) }
    }

    fun onLoginClick() {
        val state = _uiState.value
        if (state.username.isBlank() || state.password.isBlank()) {
            _uiState.update { it.copy(errorMessage = "Introduce usuario y contraseña") }
            return
        }

        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }

            when (val result = authRepository.login(state.username, state.password)) {
                is AuthRepository.AuthResult.Success -> {
                    _uiState.update { it.copy(isLoading = false, loginSuccess = true) }
                }
                is AuthRepository.AuthResult.Error -> {
                    _uiState.update {
                        it.copy(isLoading = false, errorMessage = result.message)
                    }
                }
                AuthRepository.AuthResult.NetworkError -> {
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            errorMessage = "Sin conexión. Comprueba tu red."
                        )
                    }
                }
                AuthRepository.AuthResult.SessionExpired -> {   // ← AÑADIR ESTO
                    _uiState.update {
                        it.copy(
                            isLoading    = false,
                            errorMessage = "Tu sesión ha expirado. Inicia sesión de nuevo."
                        )
                    }
                }
            }
        }
    }

    fun onNavigatedToVault() {
        _uiState.update { it.copy(loginSuccess = false) }
    }
}