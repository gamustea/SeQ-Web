package com.seq.acheronmobile.ui.vault

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.seq.acheronmobile.data.vault.StorableUi
import com.seq.acheronmobile.ui.theme.AcheronMark
import com.seq.acheronmobile.ui.theme.BrandSpace
import kotlinx.coroutines.launch

@Composable
fun VaultListScreen(
    viewModel: VaultViewModel = viewModel(),
    onAdd: (kind: String) -> Unit,
    onStorableClick: (StorableUi) -> Unit,
    onLock: () -> Unit,
    onLogout: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var showLockDialog by remember { mutableStateOf(false) }
    var showLogoutDialog by remember { mutableStateOf(false) }
    var showChangePasswordDialog by remember { mutableStateOf(false) }
    // null = "Todos"; en otro caso, el kind seleccionado.
    var filterKind by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(uiState.errorMessage) {
        uiState.errorMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearError()
        }
    }
    LaunchedEffect(uiState.locked) { if (uiState.locked) onLock() }

    if (showLockDialog) {
        AlertDialog(
            onDismissRequest = { showLockDialog = false },
            icon = { Icon(Icons.Filled.Lock, null, tint = MaterialTheme.colorScheme.primary) },
            title = { Text("Bloquear bóveda") },
            text = { Text("La bóveda se cifrará y necesitarás tu clave maestra para volver a abrirla.") },
            confirmButton = {
                TextButton(onClick = { showLockDialog = false; viewModel.lockVault() }) {
                    Text("Bloquear")
                }
            },
            dismissButton = {
                TextButton(onClick = { showLockDialog = false }) { Text("Cancelar") }
            }
        )
    }

    if (showChangePasswordDialog) {
        ChangePasswordDialog(
            busy = uiState.syncing,
            onDismiss = { showChangePasswordDialog = false },
            onConfirm = { current, next ->
                scope.launch {
                    val ok = viewModel.changeMasterPassword(current, next)
                    if (ok) showChangePasswordDialog = false
                }
            }
        )
    }

    if (showLogoutDialog) {
        AlertDialog(
            onDismissRequest = { showLogoutDialog = false },
            icon = { Icon(Icons.AutoMirrored.Filled.Logout, null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("Cerrar sesión de SeQ") },
            text = {
                Text(
                    "Se cerrará tu sesión por completo. La próxima vez deberás " +
                        "iniciar sesión de nuevo con tu usuario y contraseña de SeQ."
                )
            },
            confirmButton = {
                TextButton(onClick = { showLogoutDialog = false; onLogout() }) {
                    Text("Cerrar sesión", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { showLogoutDialog = false }) { Text("Cancelar") }
            }
        )
    }

    // Recuento por tipo, respetando el orden del registro.
    val countsByKind = uiState.storables.groupingBy { it.kind }.eachCount()
    val presentTypes = StorableTypes.all.filter { (countsByKind[it.kind] ?: 0) > 0 }
    val visible = filterKind?.let { k -> uiState.storables.filter { it.kind == k } } ?: uiState.storables

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            VaultHeader(
                syncing = uiState.syncing,
                onSync = { viewModel.syncToRemote() },
                onChangePassword = { showChangePasswordDialog = true },
                onLock = { showLockDialog = true },
                onLogout = { showLogoutDialog = true }
            )
        },
        floatingActionButton = { AddMenu(onAdd = onAdd) }
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (uiState.storables.isEmpty() && !uiState.isLoading) {
                EmptyVault(onAdd = { onAdd("account") })
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(
                        start = BrandSpace.md, end = BrandSpace.md,
                        top = BrandSpace.sm, bottom = 96.dp
                    ),
                    verticalArrangement = Arrangement.spacedBy(BrandSpace.sm)
                ) {
                    item {
                        VaultStatusStrip(count = uiState.storables.size, syncing = uiState.syncing)
                    }
                    item {
                        CategoryFilter(
                            selected = filterKind,
                            onSelect = { filterKind = it },
                            allCount = uiState.storables.size,
                            presentTypes = presentTypes,
                            countsByKind = countsByKind
                        )
                    }
                    items(visible, key = { it.id }) { storable ->
                        StorableCard(storable, onClick = { onStorableClick(storable) })
                    }
                }
            }

            if (uiState.isLoading) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
                }
            }
        }
    }
}

// ── Cabecera ──────────────────────────────────────────────────────────────────

@Composable
private fun VaultHeader(
    syncing: Boolean,
    onSync: () -> Unit,
    onChangePassword: () -> Unit,
    onLock: () -> Unit,
    onLogout: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.background)
            .statusBarsPadding()
            .padding(start = BrandSpace.md, end = BrandSpace.sm, top = BrandSpace.md, bottom = BrandSpace.sm),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AcheronMark(modifier = Modifier.size(32.dp))
        Spacer(Modifier.width(BrandSpace.sm))
        Column(Modifier.weight(1f)) {
            Text(
                "ACHERON",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onBackground,
                letterSpacing = 3.sp
            )
            Text(
                "Bóveda de secretos",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                letterSpacing = 1.sp
            )
        }
        HeaderAction(icon = Icons.Filled.Sync, desc = "Sincronizar", loading = syncing, onClick = onSync)
        Spacer(Modifier.width(BrandSpace.sm))
        HeaderAction(icon = Icons.Filled.Password, desc = "Cambiar contraseña", onClick = onChangePassword)
        Spacer(Modifier.width(BrandSpace.sm))
        HeaderAction(icon = Icons.Filled.Lock, desc = "Bloquear", onClick = onLock)
        Spacer(Modifier.width(BrandSpace.sm))
        HeaderAction(icon = Icons.AutoMirrored.Filled.Logout, desc = "Cerrar sesión", onClick = onLogout)
    }
}

@Composable
private fun HeaderAction(
    icon: ImageVector,
    desc: String,
    loading: Boolean = false,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(CircleShape)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, CircleShape)
            .clickable(enabled = !loading) { onClick() },
        contentAlignment = Alignment.Center
    ) {
        if (loading) {
            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.primary)
        } else {
            Icon(icon, contentDescription = desc, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
        }
    }
}

// ── Cambio de contraseña maestra ────────────────────────────────────────────────

@Composable
private fun ChangePasswordDialog(
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (current: String, next: String) -> Unit
) {
    var current by remember { mutableStateOf("") }
    var next by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var localError by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        icon = { Icon(Icons.Filled.Password, null, tint = MaterialTheme.colorScheme.primary) },
        title = { Text("Cambiar contraseña maestra") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(BrandSpace.sm)) {
                Text(
                    "La nueva contraseña se aplica en este dispositivo: se vuelve a " +
                        "cifrar la clave de la bóveda. Tus elementos no cambian.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutlinedTextField(
                    value = current, onValueChange = { current = it },
                    label = { Text("Contraseña actual") },
                    singleLine = true, enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = next, onValueChange = { next = it },
                    label = { Text("Nueva contraseña") },
                    singleLine = true, enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = confirm, onValueChange = { confirm = it },
                    label = { Text("Repite la nueva contraseña") },
                    singleLine = true, enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
                localError?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy,
                onClick = {
                    val err = validateNewPassword(current, next, confirm)
                    if (err != null) {
                        localError = err
                        return@TextButton
                    }
                    localError = null
                    onConfirm(current, next)
                }
            ) { Text("Cambiar") }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = onDismiss) { Text("Cancelar") }
        }
    )
}

private fun validateNewPassword(current: String, next: String, confirm: String): String? {
    val minLength = 8
    return when {
        current.isEmpty() -> "Introduce tu contraseña actual."
        next.length < minLength -> "La nueva contraseña debe tener al menos $minLength caracteres."
        next != confirm -> "Las contraseñas nuevas no coinciden."
        next == current -> "La nueva contraseña debe ser distinta de la actual."
        else -> null
    }
}

// ── Estado de la boveda ───────────────────────────────────────────────────────

@Composable
private fun VaultStatusStrip(count: Int, syncing: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.surfaceContainer)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(14.dp))
            .padding(horizontal = BrandSpace.md, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(Icons.Filled.LockOpen, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(BrandSpace.sm))
        Column(Modifier.weight(1f)) {
            Text(
                "Bóveda desbloqueada",
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onBackground
            )
            Text(
                if (syncing) "Sincronizando…" else "Cifrada de extremo a extremo",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        CountPill(count)
    }
}

@Composable
private fun CountPill(count: Int) {
    Box(
        modifier = Modifier
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.14f))
            .padding(horizontal = 12.dp, vertical = 4.dp)
    ) {
        Text(
            "$count ${if (count == 1) "elemento" else "elementos"}",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.SemiBold
        )
    }
}

// ── Filtro por categoria ──────────────────────────────────────────────────────

@Composable
private fun CategoryFilter(
    selected: String?,
    onSelect: (String?) -> Unit,
    allCount: Int,
    presentTypes: List<StorableTypeSpec>,
    countsByKind: Map<String, Int>
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(vertical = BrandSpace.xs),
        horizontalArrangement = Arrangement.spacedBy(BrandSpace.sm)
    ) {
        FilterChip("Todos", allCount, selected == null) { onSelect(null) }
        presentTypes.forEach { type ->
            FilterChip(
                label = type.plural,
                count = countsByKind[type.kind] ?: 0,
                selected = selected == type.kind
            ) { onSelect(type.kind) }
        }
    }
}

@Composable
private fun FilterChip(label: String, count: Int, selected: Boolean, onClick: () -> Unit) {
    val shape = CircleShape
    Box(
        modifier = Modifier
            .clip(shape)
            .background(if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.16f) else Color.Transparent)
            .border(1.dp, if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant, shape)
            .clickable { onClick() }
            .padding(horizontal = 14.dp, vertical = 7.dp)
    ) {
        Text(
            "$label · $count",
            style = MaterialTheme.typography.labelMedium,
            color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
            maxLines = 1
        )
    }
}

// ── Tarjeta de elemento ───────────────────────────────────────────────────────

@Composable
private fun StorableCard(storable: StorableUi, onClick: () -> Unit) {
    val spec = StorableTypes.of(storable.kind)
    val accent = spec.accentColor()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surfaceContainer)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(16.dp))
            .clickable { onClick() }
            .padding(BrandSpace.md),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(44.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(accent.copy(alpha = 0.14f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                spec.icon,
                contentDescription = spec.label,
                tint = accent,
                modifier = Modifier.size(22.dp)
            )
        }
        Spacer(Modifier.width(BrandSpace.md))
        Column(Modifier.weight(1f)) {
            Text(
                storable.title,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onBackground,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            val sub = spec.subtitleKey?.let { storable.details[it] }
            if (!sub.isNullOrBlank()) {
                Text(
                    sub,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
        }
        Icon(
            Icons.Filled.ChevronRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
            modifier = Modifier.size(20.dp)
        )
    }
}

// ── Estado vacio ──────────────────────────────────────────────────────────────

@Composable
private fun EmptyVault(onAdd: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(BrandSpace.xl),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        AcheronMark(modifier = Modifier.size(72.dp))
        Spacer(Modifier.height(BrandSpace.lg))
        Text(
            "Tu bóveda está vacía",
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground
        )
        Spacer(Modifier.height(BrandSpace.xs))
        Text(
            "Guarda tu primer secreto. Todo se cifra antes de salir de este dispositivo.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = BrandSpace.md),
            maxLines = 3
        )
        Spacer(Modifier.height(BrandSpace.lg))
        com.seq.acheronmobile.ui.theme.BrandPrimaryButton(
            text = "Añadir credencial",
            onClick = onAdd,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

// ── Menu de añadir ────────────────────────────────────────────────────────────

@Composable
private fun AddMenu(onAdd: (kind: String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(BrandSpace.sm)) {
        AnimatedVisibility(visible = open, enter = fadeIn(), exit = fadeOut()) {
            Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(BrandSpace.sm)) {
                StorableTypes.all.forEach { type ->
                    AddMenuItem(
                        label = type.newLabel,
                        icon = type.icon,
                        accent = type.accent ?: MaterialTheme.colorScheme.primary
                    ) {
                        open = false; onAdd(type.kind)
                    }
                }
            }
        }
        FloatingActionButton(
            onClick = { open = !open },
            containerColor = MaterialTheme.colorScheme.primary,
            contentColor = MaterialTheme.colorScheme.onPrimary
        ) {
            Icon(Icons.Filled.Add, contentDescription = if (open) "Cerrar" else "Añadir")
        }
    }
}

@Composable
private fun AddMenuItem(
    label: String,
    icon: ImageVector,
    accent: Color,
    onClick: () -> Unit
) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(BrandSpace.sm)) {
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(10.dp))
                .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(10.dp))
                .padding(horizontal = 12.dp, vertical = 8.dp)
        ) {
            Text(label, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onBackground)
        }
        Box(
            modifier = Modifier
                .size(44.dp)
                .clip(CircleShape)
                .background(accent.copy(alpha = 0.16f))
                .border(1.dp, accent.copy(alpha = 0.5f), CircleShape)
                .clickable { onClick() },
            contentAlignment = Alignment.Center
        ) {
            Icon(icon, contentDescription = label, tint = accent, modifier = Modifier.size(20.dp))
        }
    }
}
