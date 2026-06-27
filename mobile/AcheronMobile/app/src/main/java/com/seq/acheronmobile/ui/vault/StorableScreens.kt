package com.seq.acheronmobile.ui.vault

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.seq.acheronmobile.data.vault.StorableUi
import com.seq.acheronmobile.ui.theme.BrandField
import com.seq.acheronmobile.ui.theme.BrandPanel
import com.seq.acheronmobile.ui.theme.BrandPrimaryButton
import com.seq.acheronmobile.ui.theme.BrandSpace
import com.seq.acheronmobile.ui.theme.SectionLabel
import com.seq.acheronmobile.ui.theme.secretTextStyle
import kotlinx.coroutines.launch

// ── Barra superior de marca ───────────────────────────────────────────────────

@Composable
private fun BrandTopBar(
    title: String,
    onBack: () -> Unit,
    actions: @Composable () -> Unit = {}
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.background)
            .statusBarsPadding()
            .padding(horizontal = BrandSpace.sm, vertical = BrandSpace.sm),
        verticalAlignment = Alignment.CenterVertically
    ) {
        IconButton(onClick = onBack) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, "Volver", tint = MaterialTheme.colorScheme.onBackground)
        }
        Text(
            title,
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onBackground,
            modifier = Modifier.weight(1f).padding(start = BrandSpace.xs),
            maxLines = 1
        )
        actions()
    }
}

// ── Detalle ───────────────────────────────────────────────────────────────────

@Composable
fun StorableDetailScreen(
    storable: StorableUi,
    vaultViewModel: VaultViewModel = viewModel(),
    onBack: () -> Unit,
    onDeleted: () -> Unit
) {
    var showDeleteDialog by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val snackbarHostState = remember { SnackbarHostState() }

    val uiState by vaultViewModel.uiState.collectAsState()
    val currentStorable = uiState.storables.find { it.id == storable.id } ?: storable

    val spec = StorableTypes.of(currentStorable.kind)
    val accent = spec.accentColor()

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            icon = { Icon(Icons.Filled.Delete, null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("Eliminar «${currentStorable.title}»") },
            text = { Text("Esta acción es irreversible. El elemento se borrará de tu bóveda.") },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteDialog = false
                    scope.launch { if (vaultViewModel.deleteStorable(currentStorable.id)) onDeleted() }
                }) { Text("Eliminar", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { showDeleteDialog = false }) { Text("Cancelar") } }
        )
    }

    if (editing) {
        StorableFormScreen(
            storable = currentStorable,
            vaultViewModel = vaultViewModel,
            onSaved = { editing = false },
            onBack = { editing = false }
        )
        return
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            BrandTopBar(title = currentStorable.title, onBack = onBack) {
                IconButton(onClick = { editing = true }) {
                    Icon(Icons.Filled.Edit, "Editar", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                IconButton(onClick = { showDeleteDialog = true }) {
                    Icon(Icons.Filled.Delete, "Eliminar", tint = MaterialTheme.colorScheme.error)
                }
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = BrandSpace.md, vertical = BrandSpace.sm),
            verticalArrangement = Arrangement.spacedBy(BrandSpace.md)
        ) {
            // Hero
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(52.dp)
                        .clip(RoundedCornerShape(14.dp))
                        .background(accent.copy(alpha = 0.14f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        spec.icon,
                        contentDescription = null, tint = accent, modifier = Modifier.size(26.dp)
                    )
                }
                Spacer(Modifier.width(BrandSpace.md))
                Column {
                    Text(
                        currentStorable.title,
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Text(
                        spec.label,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        letterSpacing = 1.sp
                    )
                }
            }

            BrandPanel(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(BrandSpace.md),
                    verticalArrangement = Arrangement.spacedBy(BrandSpace.md)
                ) {
                    SectionLabel("Detalles")
                    currentStorable.details.forEach { (key, value) ->
                        val field = spec.field(key)
                        DetailField(
                            label = field?.label ?: key,
                            value = value,
                            masked = field?.secret == true,
                            onCopy = {
                                clipboard.setText(AnnotatedString(value))
                                scope.launch { snackbarHostState.showSnackbar("${field?.label ?: key} copiado") }
                            }
                        )
                    }
                }
            }

            BrandPanel(modifier = Modifier.fillMaxWidth(), accent = false) {
                Column(
                    modifier = Modifier.padding(BrandSpace.md),
                    verticalArrangement = Arrangement.spacedBy(BrandSpace.xs)
                ) {
                    MetaRow("Creado", currentStorable.createdAt.take(19).replace('T', ' '))
                    MetaRow("Actualizado", currentStorable.updatedAt.take(19).replace('T', ' '))
                }
            }
        }
    }
}

@Composable
private fun DetailField(label: String, value: String, masked: Boolean, onCopy: () -> Unit) {
    var revealed by remember { mutableStateOf(!masked) }
    Column(verticalArrangement = Arrangement.spacedBy(BrandSpace.xs)) {
        SectionLabel(label)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (revealed) value else "•".repeat(value.length.coerceIn(6, 12)),
                style = if (masked) secretTextStyle() else MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.weight(1f)
            )
            if (masked) {
                IconButton(onClick = { revealed = !revealed }, modifier = Modifier.size(36.dp)) {
                    Icon(
                        if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = if (revealed) "Ocultar" else "Mostrar",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
            IconButton(onClick = onCopy, modifier = Modifier.size(36.dp)) {
                Icon(
                    Icons.Filled.ContentCopy, contentDescription = "Copiar",
                    tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp)
                )
            }
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f)))
    }
}

@Composable
private fun MetaRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ── Formulario (alta / edicion) ───────────────────────────────────────────────

@Composable
fun StorableFormScreen(
    storable: StorableUi? = null,
    vaultViewModel: VaultViewModel = viewModel(),
    defaultKind: String = "account",
    onSaved: () -> Unit,
    onBack: () -> Unit
) {
    val isEdit = storable != null
    var kind by remember { mutableStateOf(storable?.kind ?: defaultKind) }
    val spec = StorableTypes.of(kind)
    val accent = spec.accentColor()

    var title by remember(kind) { mutableStateOf(storable?.title ?: "") }

    // Valores y visibilidad por campo. Se reinician al cambiar de tipo (alta).
    // En edición, los campos `prefill` se pre-rellenan con el valor actual; los
    // secretos no prefill (p. ej. el PAN llega enmascarado) se dejan vacíos para
    // que "vacío = sin cambios" y nunca se corrompa el valor real al guardar.
    val values = remember(kind) {
        mutableStateMapOf<String, String>().apply {
            spec.fields.forEach { f ->
                put(f.key, if (isEdit && f.prefill) storable?.details?.get(f.key).orEmpty() else "")
            }
        }
    }
    val revealed = remember(kind) { mutableStateMapOf<String, Boolean>() }

    var saving by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val uiState by vaultViewModel.uiState.collectAsState()

    // Validación de longitud mínima (p. ej. número de tarjeta ≥ 4):
    // en alta exige el mínimo; en edición, vacío = sin cambios.
    fun fieldValid(f: FieldSpec): Boolean {
        if (f.minLength <= 0) return true
        val v = values[f.key].orEmpty().trim()
        return (isEdit && v.isBlank()) || v.length >= f.minLength
    }
    val allValid = spec.fields.all { fieldValid(it) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            BrandTopBar(
                title = if (isEdit) "Editar" else spec.newLabel,
                onBack = onBack
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = BrandSpace.md, vertical = BrandSpace.sm),
            verticalArrangement = Arrangement.spacedBy(BrandSpace.md)
        ) {
            if (!isEdit) {
                KindSelector(selected = kind, onSelect = { kind = it })
            }

            BrandPanel(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(BrandSpace.md),
                    verticalArrangement = Arrangement.spacedBy(BrandSpace.md)
                ) {
                    SectionLabel("Datos · ${spec.label}")

                    BrandField(value = title, onValueChange = { title = it }, label = "Título")

                    spec.fields.forEach { f ->
                        val visible = revealed[f.key] == true
                        BrandField(
                            value = values[f.key].orEmpty(),
                            onValueChange = { values[f.key] = it },
                            label = when {
                                isEdit && f.secret && !f.prefill -> "${f.label} (vacío = sin cambios)"
                                else -> f.label
                            },
                            singleLine = !f.multiline,
                            isError = !fieldValid(f),
                            supportingText = if (!fieldValid(f)) "Debe tener al menos ${f.minLength} caracteres" else null,
                            keyboardOptions = KeyboardOptions(
                                keyboardType = if (f.numeric) KeyboardType.Number else KeyboardType.Text,
                                imeAction = if (f == spec.fields.last()) ImeAction.Done else ImeAction.Next
                            ),
                            visualTransformation = if (f.secret && !visible) PasswordVisualTransformation() else VisualTransformation.None,
                            textStyle = if (f.secret) secretTextStyle() else MaterialTheme.typography.bodyLarge,
                            trailing = if (f.secret) {
                                {
                                    IconButton(onClick = { revealed[f.key] = !visible }) {
                                        Icon(
                                            if (visible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                            contentDescription = if (visible) "Ocultar" else "Mostrar"
                                        )
                                    }
                                }
                            } else null
                        )
                    }

                    uiState.errorMessage?.let { message ->
                        Text(message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            BrandPrimaryButton(
                text = if (isEdit) "Guardar cambios" else "Crear",
                onClick = {
                    saving = true
                    scope.launch {
                        val ok = if (isEdit && storable != null) {
                            val changes = spec.fields.associate { it.key to values[it.key]?.ifBlank { null } }
                            vaultViewModel.updateStorable(storable.id, title.ifBlank { null }, changes)
                        } else {
                            val fields = spec.fields.associate { it.key to values[it.key].orEmpty() }
                            vaultViewModel.addStorable(kind, title, fields)
                        }
                        saving = false
                        if (ok) onSaved()
                    }
                },
                enabled = !saving && title.isNotBlank() && allValid,
                loading = saving,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(BrandSpace.md))
        }
    }
}

@Composable
private fun KindSelector(selected: String, onSelect: (String) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(BrandSpace.sm)
    ) {
        StorableTypes.all.forEach { type ->
            KindOption(
                label = type.label,
                icon = type.icon,
                accent = type.accent ?: MaterialTheme.colorScheme.primary,
                selected = type.kind == selected,
                onClick = { onSelect(type.kind) }
            )
        }
    }
}

@Composable
private fun KindOption(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    accent: Color,
    selected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(14.dp))
            .background(if (selected) accent.copy(alpha = 0.14f) else MaterialTheme.colorScheme.surfaceContainer)
            .border(1.dp, if (selected) accent else MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(14.dp))
            .clickable { onClick() }
            .padding(horizontal = 14.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, tint = if (selected) accent else MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(BrandSpace.xs))
        Text(
            label,
            style = MaterialTheme.typography.titleSmall,
            color = if (selected) accent else MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
            maxLines = 1
        )
    }
}
