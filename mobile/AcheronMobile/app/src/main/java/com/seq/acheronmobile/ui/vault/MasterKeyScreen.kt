package com.seq.acheronmobile.ui.vault

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.seq.acheronmobile.ui.theme.AcheronAuthScaffold
import com.seq.acheronmobile.ui.theme.AcheronGold
import com.seq.acheronmobile.ui.theme.AcheronLockup
import com.seq.acheronmobile.ui.theme.BrandPanel
import com.seq.acheronmobile.ui.theme.BrandPrimaryButton
import com.seq.acheronmobile.ui.theme.BrandSecondaryButton
import com.seq.acheronmobile.ui.theme.BrandSpace
import com.seq.acheronmobile.ui.theme.BrandField
import com.seq.acheronmobile.ui.theme.PasswordStrengthMeter
import com.seq.acheronmobile.ui.theme.SectionLabel
import com.seq.acheronmobile.ui.theme.WarningCallout

/**
 * Puerta de la boveda. Comprueba por adelantado si el usuario tiene boveda y
 * encamina a la pantalla correcta:
 *  - comprobando        -> indicador de marca
 *  - la comprobacion fallo -> reintento
 *  - existe boveda      -> desbloqueo (clave maestra)
 *  - no existe          -> bienvenida + creacion de boveda
 */
@Composable
fun MasterKeyScreen(
    viewModel: MasterKeyViewModel = viewModel(),
    onVaultUnlocked: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(uiState.unlocked) {
        if (uiState.unlocked) {
            onVaultUnlocked()
            viewModel.onNavigatedToVault()
        }
    }

    AcheronAuthScaffold {
        Crossfade(
            targetState = uiState.vaultExists,
            animationSpec = tween(400),
            label = "vaultGate"
        ) { exists ->
            when {
                uiState.probeError != null ->
                    ProbeErrorContent(uiState.probeError!!, onRetry = viewModel::checkVault)
                exists == null ->
                    ProbeLoadingContent()
                exists ->
                    UnlockContent(viewModel, uiState)
                else ->
                    CreateVaultContent(viewModel, uiState)
            }
        }
    }
}

// ── Comprobando ───────────────────────────────────────────────────────────────

@Composable
private fun ProbeLoadingContent() {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(BrandSpace.lg)
    ) {
        AcheronLockup(subtitle = null)
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(BrandSpace.sm)
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(18.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.primary
            )
            Text(
                "Verificando tu bóveda…",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// ── Error de comprobacion ─────────────────────────────────────────────────────

@Composable
private fun ProbeErrorContent(message: String, onRetry: () -> Unit) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(BrandSpace.lg)
    ) {
        AcheronLockup(subtitle = null)
        BrandPanel(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(BrandSpace.lg),
                verticalArrangement = Arrangement.spacedBy(BrandSpace.md)
            ) {
                SectionLabel("No se pudo comprobar la bóveda")
                Text(
                    message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                BrandPrimaryButton(
                    text = "Reintentar",
                    onClick = onRetry,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }
    }
}

// ── Desbloqueo (existe boveda) ────────────────────────────────────────────────

@Composable
private fun UnlockContent(
    viewModel: MasterKeyViewModel,
    uiState: MasterKeyUiState
) {
    val focusManager = LocalFocusManager.current
    var visible by remember { mutableStateOf(false) }

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(BrandSpace.lg)
    ) {
        AcheronLockup(subtitle = null)

        BrandPanel(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(BrandSpace.lg),
                verticalArrangement = Arrangement.spacedBy(BrandSpace.md)
            ) {
                SectionLabel("Desbloquear bóveda")
                Text(
                    "Bienvenido de nuevo",
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.onBackground
                )
                Text(
                    "Introduce tu clave maestra para descifrar tu bóveda en este dispositivo.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                BrandField(
                    value = uiState.masterPassword,
                    onValueChange = viewModel::onPasswordChange,
                    label = "Clave maestra",
                    leadingIcon = Icons.Filled.Lock,
                    visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(onDone = {
                        focusManager.clearFocus(); viewModel.onUnlockClick()
                    }),
                    isError = uiState.errorMessage != null,
                    enabled = !uiState.isLoading,
                    trailing = {
                        IconButton(onClick = { visible = !visible }) {
                            Icon(
                                if (visible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (visible) "Ocultar" else "Mostrar"
                            )
                        }
                    }
                )

                ErrorLine(uiState.errorMessage)

                BrandPrimaryButton(
                    text = "Acceder a la bóveda",
                    onClick = { focusManager.clearFocus(); viewModel.onUnlockClick() },
                    enabled = !uiState.isLoading,
                    loading = uiState.isLoading,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        TrustFooter("Tu clave maestra nunca sale de este dispositivo.")
    }
}

// ── Bienvenida + creacion (no existe boveda) ──────────────────────────────────

@Composable
private fun CreateVaultContent(
    viewModel: MasterKeyViewModel,
    uiState: MasterKeyUiState
) {
    val focusManager = LocalFocusManager.current
    var visible by remember { mutableStateOf(false) }
    var visibleConfirm by remember { mutableStateOf(false) }

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(BrandSpace.lg)
    ) {
        AcheronLockup(subtitle = null)

        BrandPanel(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(BrandSpace.lg),
                verticalArrangement = Arrangement.spacedBy(BrandSpace.md)
            ) {
                SectionLabel("Primer acceso")
                Text(
                    "Bienvenido a Acheron",
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.onBackground
                )
                Text(
                    "Aún no cuentas con una bóveda de contraseñas. Define tu clave maestra " +
                        "para crearla y empezar a custodiar tus secretos.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                WarningCallout(
                    icon = Icons.Outlined.Shield,
                    title = "Tu clave maestra es esencial",
                    body = "Es la única llave para desbloquear tu bóveda y acceder a tus secretos. " +
                        "No se guarda en ningún servidor y nadie —ni nosotros— puede recuperarla. " +
                        "Guárdala en un lugar seguro y no la compartas con nadie."
                )

                BrandField(
                    value = uiState.masterPassword,
                    onValueChange = viewModel::onPasswordChange,
                    label = "Clave maestra",
                    leadingIcon = Icons.Filled.Lock,
                    visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Next),
                    isError = uiState.errorMessage != null,
                    enabled = !uiState.isLoading,
                    trailing = {
                        IconButton(onClick = { visible = !visible }) {
                            Icon(
                                if (visible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (visible) "Ocultar" else "Mostrar"
                            )
                        }
                    }
                )

                PasswordStrengthMeter(uiState.masterPassword)

                BrandField(
                    value = uiState.confirmPassword,
                    onValueChange = viewModel::onConfirmChange,
                    label = "Confirmar clave maestra",
                    leadingIcon = Icons.Filled.Lock,
                    visualTransformation = if (visibleConfirm) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(onDone = {
                        focusManager.clearFocus(); viewModel.onCreateVaultClick()
                    }),
                    isError = uiState.errorMessage != null,
                    enabled = !uiState.isLoading,
                    trailing = {
                        IconButton(onClick = { visibleConfirm = !visibleConfirm }) {
                            Icon(
                                if (visibleConfirm) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (visibleConfirm) "Ocultar" else "Mostrar"
                            )
                        }
                    }
                )

                ErrorLine(uiState.errorMessage)

                BrandPrimaryButton(
                    text = "Crear mi bóveda",
                    onClick = { focusManager.clearFocus(); viewModel.onCreateVaultClick() },
                    enabled = !uiState.isLoading,
                    loading = uiState.isLoading,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        TrustFooter("Cifrado de extremo a extremo. Solo tú tienes la llave.")
    }
}

// ── Auxiliares ────────────────────────────────────────────────────────────────

@Composable
private fun ErrorLine(message: String?) {
    AnimatedVisibility(visible = message != null, enter = fadeIn(), exit = fadeOut()) {
        message?.let {
            Text(
                text = it,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
private fun TrustFooter(text: String) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(BrandSpace.sm)
    ) {
        Icon(
            Icons.Outlined.VerifiedUser,
            contentDescription = null,
            tint = AcheronGold.copy(alpha = 0.8f),
            modifier = Modifier.size(14.dp)
        )
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.Medium,
            letterSpacing = 0.5.sp
        )
    }
}
