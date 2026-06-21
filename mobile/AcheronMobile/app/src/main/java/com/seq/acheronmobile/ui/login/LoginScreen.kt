package com.seq.acheronmobile.ui.login

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.seq.acheronmobile.ui.theme.AcheronAuthScaffold
import com.seq.acheronmobile.ui.theme.AcheronLockup
import com.seq.acheronmobile.ui.theme.BrandField
import com.seq.acheronmobile.ui.theme.BrandPanel
import com.seq.acheronmobile.ui.theme.BrandPrimaryButton
import com.seq.acheronmobile.ui.theme.BrandSpace
import com.seq.acheronmobile.ui.theme.SectionLabel

@Composable
fun LoginScreen(
    viewModel: LoginViewModel,
    onLoginSuccess: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val focusManager = LocalFocusManager.current
    var passwordVisible by remember { mutableStateOf(false) }

    LaunchedEffect(uiState.loginSuccess) {
        if (uiState.loginSuccess) {
            onLoginSuccess()
            viewModel.onNavigatedToVault()
        }
    }

    AcheronAuthScaffold {
        AcheronLockup(subtitle = "El guardián de tus secretos en la travesía.")

        BrandPanel(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(BrandSpace.lg),
                verticalArrangement = Arrangement.spacedBy(BrandSpace.md)
            ) {
                SectionLabel("Acceso al sistema")
                Text(
                    "Inicia sesión",
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.onBackground
                )

                BrandField(
                    value = uiState.username,
                    onValueChange = viewModel::onUsernameChange,
                    label = "Usuario",
                    leadingIcon = Icons.Filled.Person,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Text, imeAction = ImeAction.Next
                    ),
                    keyboardActions = KeyboardActions(
                        onNext = { focusManager.moveFocus(FocusDirection.Down) }
                    ),
                    isError = uiState.errorMessage != null,
                    enabled = !uiState.isLoading
                )

                BrandField(
                    value = uiState.password,
                    onValueChange = viewModel::onPasswordChange,
                    label = "Contraseña",
                    leadingIcon = Icons.Filled.Lock,
                    visualTransformation = if (passwordVisible)
                        VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password, imeAction = ImeAction.Done
                    ),
                    keyboardActions = KeyboardActions(
                        onDone = { focusManager.clearFocus(); viewModel.onLoginClick() }
                    ),
                    isError = uiState.errorMessage != null,
                    enabled = !uiState.isLoading,
                    trailing = {
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Icon(
                                imageVector = if (passwordVisible)
                                    Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (passwordVisible)
                                    "Ocultar contraseña" else "Mostrar contraseña"
                            )
                        }
                    }
                )

                AnimatedVisibility(
                    visible = uiState.errorMessage != null,
                    enter = fadeIn(), exit = fadeOut()
                ) {
                    uiState.errorMessage?.let { msg ->
                        Text(
                            text = msg,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }

                BrandPrimaryButton(
                    text = "Iniciar sesión",
                    onClick = { focusManager.clearFocus(); viewModel.onLoginClick() },
                    enabled = !uiState.isLoading,
                    loading = uiState.isLoading,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        Text(
            "SeQ · SecOps Platform",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = BrandSpace.sm)
        )
    }
}
