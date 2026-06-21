package com.seq.acheronmobile.ui.vault

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Person
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.seq.acheronmobile.data.vault.StorableUi
import com.seq.acheronmobile.ui.theme.AcheronGold
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

    val isAccount = currentStorable.kind == "account"
    val accent = if (isAccount) MaterialTheme.colorScheme.primary else AcheronGold

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
                        if (isAccount) Icons.Filled.Person else Icons.Filled.CreditCard,
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
                        if (isAccount) "Cuenta" else "Tarjeta",
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
                        DetailField(
                            label = fieldLabel(key),
                            value = value,
                            masked = shouldMask(key),
                            onCopy = {
                                clipboard.setText(AnnotatedString(value))
                                scope.launch { snackbarHostState.showSnackbar("${fieldLabel(key)} copiado") }
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
    var title by remember { mutableStateOf(storable?.title ?: "") }
    var username by remember { mutableStateOf(storable?.details?.get("username") ?: "") }
    var domain by remember { mutableStateOf(storable?.details?.get("domain") ?: "") }
    var password by remember { mutableStateOf("") }
    var holder by remember { mutableStateOf(storable?.details?.get("cardHolderName") ?: "") }
    // El numero de tarjeta llega enmascarado ("****1234") desde el listado/detalle;
    // pre-rellenarlo aqui corromperia el PAN real al guardar (ver hallazgo #4).
    var number by remember { mutableStateOf("") }
    var expiry by remember { mutableStateOf(storable?.details?.get("expirationDate") ?: "") }
    var cvv by remember { mutableStateOf("") }
    var postal by remember { mutableStateOf(storable?.details?.get("postalCode") ?: "") }
    var saving by remember { mutableStateOf(false) }
    var passwordVisible by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val uiState by vaultViewModel.uiState.collectAsState()
    val isCardKind = kind == "creditcard"
    // En alta, el numero es obligatorio; en edicion, vacio = sin cambios,
    // pero si se reintroduce debe tener al menos 4 cifras (evita el crash de #5).
    val cardNumberValid = !isCardKind || (isEdit && number.isBlank()) || number.trim().length >= 4

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            BrandTopBar(
                title = if (isEdit) "Editar" else if (isCardKind) "Nueva tarjeta" else "Nueva cuenta",
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
                KindSelector(kind = kind, onSelect = { kind = it })
            }

            BrandPanel(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(BrandSpace.md),
                    verticalArrangement = Arrangement.spacedBy(BrandSpace.md)
                ) {
                    SectionLabel(if (isCardKind) "Datos de la tarjeta" else "Datos de la cuenta")

                    BrandField(value = title, onValueChange = { title = it }, label = "Título")

                    if (kind == "account") {
                        BrandField(value = username, onValueChange = { username = it }, label = "Usuario / Email")
                        BrandField(value = domain, onValueChange = { domain = it }, label = "Dominio / Servicio")
                        BrandField(
                            value = password, onValueChange = { password = it },
                            label = if (isEdit) "Nueva contraseña (vacío = sin cambios)" else "Contraseña",
                            visualTransformation = if (passwordVisible) androidx.compose.ui.text.input.VisualTransformation.None else PasswordVisualTransformation(),
                            textStyle = secretTextStyle(),
                            trailing = {
                                IconButton(onClick = { passwordVisible = !passwordVisible }) {
                                    Icon(
                                        if (passwordVisible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                        contentDescription = if (passwordVisible) "Ocultar" else "Mostrar"
                                    )
                                }
                            }
                        )
                    } else {
                        BrandField(value = holder, onValueChange = { holder = it }, label = "Titular")
                        BrandField(
                            value = number, onValueChange = { number = it },
                            label = if (isEdit) "Nuevo número (vacío = sin cambios)" else "Número de tarjeta",
                            isError = !cardNumberValid,
                            supportingText = if (!cardNumberValid) "Debe tener al menos 4 cifras" else null,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            textStyle = secretTextStyle()
                        )
                        BrandField(
                            value = expiry, onValueChange = { expiry = it },
                            label = "Caducidad (MM/YY)"
                        )
                        BrandField(
                            value = cvv, onValueChange = { cvv = it },
                            label = if (isEdit) "Nuevo CVV (vacío = sin cambios)" else "CVV",
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Done),
                            visualTransformation = PasswordVisualTransformation(),
                            textStyle = secretTextStyle()
                        )
                        BrandField(value = postal, onValueChange = { postal = it }, label = "Código postal")
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
                            if (kind == "account")
                                vaultViewModel.updateAccount(storable.id, title.ifBlank { null }, username.ifBlank { null }, domain.ifBlank { null }, password.ifBlank { null })
                            else
                                vaultViewModel.updateCreditCard(storable.id, title.ifBlank { null }, holder.ifBlank { null }, number.ifBlank { null }, expiry.ifBlank { null }, cvv.ifBlank { null }, postal.ifBlank { null })
                        } else {
                            if (kind == "account")
                                vaultViewModel.addAccount(title, username, domain, password)
                            else
                                vaultViewModel.addCreditCard(title, holder, number, expiry, cvv, postal)
                        }
                        saving = false
                        if (ok) onSaved()
                    }
                },
                enabled = !saving && title.isNotBlank() && cardNumberValid,
                loading = saving,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(BrandSpace.md))
        }
    }
}

@Composable
private fun KindSelector(kind: String, onSelect: (String) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(BrandSpace.sm)
    ) {
        KindOption("Cuenta", Icons.Filled.Person, MaterialTheme.colorScheme.primary, kind == "account", Modifier.weight(1f)) { onSelect("account") }
        KindOption("Tarjeta", Icons.Filled.CreditCard, AcheronGold, kind == "creditcard", Modifier.weight(1f)) { onSelect("creditcard") }
    }
}

@Composable
private fun KindOption(
    label: String, icon: ImageVector, accent: Color, selected: Boolean,
    modifier: Modifier = Modifier, onClick: () -> Unit
) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .background(if (selected) accent.copy(alpha = 0.14f) else MaterialTheme.colorScheme.surfaceContainer)
            .border(1.dp, if (selected) accent else MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(14.dp))
            .clickable { onClick() }
            .padding(vertical = 14.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, tint = if (selected) accent else MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(BrandSpace.sm))
        Text(
            label,
            style = MaterialTheme.typography.titleSmall,
            color = if (selected) accent else MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal
        )
    }
}

private fun fieldLabel(key: String): String = when (key) {
    "username" -> "Usuario"
    "domain" -> "Dominio"
    "password" -> "Contraseña"
    "cardHolderName" -> "Titular"
    "cardNumber" -> "Número de tarjeta"
    "expirationDate" -> "Caducidad"
    "postalCode" -> "Código postal"
    "cvv" -> "CVV"
    else -> key
}

private fun shouldMask(key: String): Boolean = key in setOf("password", "cvv", "cardNumber")
