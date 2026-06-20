package com.seq.acheronmobile.ui.vault

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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.seq.acheronmobile.data.vault.StorableUi

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StorableDetailScreen(
    storable: StorableUi,
    vaultViewModel: VaultViewModel = viewModel(),
    onBack: () -> Unit,
    onDeleted: () -> Unit
) {
    var showDeleteDialog by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf(false) }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text("Eliminar \"${storable.title}\"") },
            text = { Text("Esta accion es irreversible.") },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteDialog = false
                    vaultViewModel.deleteStorable(storable.id)
                    onDeleted()
                }) { Text("Eliminar", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) { Text("Cancelar") }
            }
        )
    }

    if (editing) {
        StorableFormScreen(
            storable = storable,
            vaultViewModel = vaultViewModel,
            onSaved = { editing = false },
            onBack = { editing = false }
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(storable.title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Volver")
                    }
                },
                actions = {
                    IconButton(onClick = { editing = true }) {
                        Icon(Icons.Filled.Edit, "Editar")
                    }
                    IconButton(onClick = { showDeleteDialog = true }) {
                        Icon(Icons.Filled.Delete, "Eliminar",
                            tint = MaterialTheme.colorScheme.error)
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(
                imageVector = if (storable.kind == "account") Icons.Filled.Person else Icons.Filled.CreditCard,
                contentDescription = null,
                modifier = Modifier.size(48.dp).align(Alignment.CenterHorizontally),
                tint = MaterialTheme.colorScheme.primary
            )
            Text(
                "Tipo: ${if (storable.kind == "account") "Cuenta" else "Tarjeta"}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
            )) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    storable.details.forEach { (key, value) ->
                        val label = fieldLabel(key)
                        val masked = shouldMask(key)
                        var visible by remember { mutableStateOf(!masked) }
                        Column {
                            Text(label, style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                            if (masked) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = if (visible) value else "********",
                                        style = MaterialTheme.typography.bodyMedium,
                                        modifier = Modifier.weight(1f)
                                    )
                                    TextButton(onClick = { visible = !visible }) {
                                        Text(if (visible) "Ocultar" else "Mostrar",
                                            style = MaterialTheme.typography.labelSmall)
                                    }
                                }
                            } else {
                                Text(value, style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                    }
                    Text("Creado: ${storable.createdAt.take(19)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text("Actualizado: ${storable.updatedAt.take(19)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
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
    var number by remember { mutableStateOf(storable?.details?.get("cardNumber") ?: "") }
    var expiry by remember { mutableStateOf(storable?.details?.get("expirationDate") ?: "") }
    var cvv by remember { mutableStateOf("") }
    var postal by remember { mutableStateOf(storable?.details?.get("postalCode") ?: "") }
    var saving by remember { mutableStateOf(false) }
    var kindExpanded by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (isEdit) "Editar" else "Nuevo") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Volver")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (!isEdit) {
                ExposedDropdownMenuBox(expanded = kindExpanded,
                    onExpandedChange = { kindExpanded = !kindExpanded }) {
                    OutlinedTextField(
                        value = if (kind == "account") "Cuenta" else "Tarjeta",
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Tipo") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = kindExpanded) },
                        modifier = Modifier.fillMaxWidth().menuAnchor()
                    )
                    ExposedDropdownMenu(expanded = kindExpanded,
                        onDismissRequest = { kindExpanded = false }) {
                        DropdownMenuItem(text = { Text("Cuenta") },
                            onClick = { kind = "account"; kindExpanded = false })
                        DropdownMenuItem(text = { Text("Tarjeta") },
                            onClick = { kind = "creditcard"; kindExpanded = false })
                    }
                }
            }

            OutlinedTextField(value = title, onValueChange = { title = it },
                label = { Text("Titulo") }, singleLine = true,
                modifier = Modifier.fillMaxWidth())

            if (kind == "account") {
                OutlinedTextField(value = username, onValueChange = { username = it },
                    label = { Text("Usuario / Email") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = domain, onValueChange = { domain = it },
                    label = { Text("Dominio / Servicio") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = password, onValueChange = { password = it },
                    label = { Text(if (isEdit) "Nueva contrasena (dejar vacio = sin cambios)" else "Contrasena") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = PasswordVisualTransformation())
            } else {
                OutlinedTextField(value = holder, onValueChange = { holder = it },
                    label = { Text("Titular") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = number, onValueChange = { number = it },
                    label = { Text("Numero de tarjeta") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
                OutlinedTextField(value = expiry, onValueChange = { expiry = it },
                    label = { Text("Caducidad (MM/YY)") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = cvv, onValueChange = { cvv = it },
                    label = { Text(if (isEdit) "Nuevo CVV (dejar vacio = sin cambios)" else "CVV") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    visualTransformation = PasswordVisualTransformation())
                OutlinedTextField(value = postal, onValueChange = { postal = it },
                    label = { Text("Codigo postal") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth())
            }

            Spacer(Modifier.height(8.dp))

            Button(
                onClick = {
                    saving = true
                    if (isEdit && storable != null) {
                        if (kind == "account") {
                            vaultViewModel.updateAccount(storable.id,
                                title.ifBlank { null }, username.ifBlank { null },
                                domain.ifBlank { null }, password.ifBlank { null })
                        } else {
                            vaultViewModel.updateCreditCard(storable.id,
                                title.ifBlank { null }, holder.ifBlank { null },
                                number.ifBlank { null }, expiry.ifBlank { null },
                                cvv.ifBlank { null }, postal.ifBlank { null })
                        }
                    } else {
                        if (kind == "account") {
                            vaultViewModel.addAccount(title, username, domain, password)
                        } else {
                            vaultViewModel.addCreditCard(title, holder, number, expiry, cvv, postal)
                        }
                    }
                    saving = false
                    onSaved()
                },
                modifier = Modifier.fillMaxWidth().height(52.dp),
                enabled = !saving && title.isNotBlank()
            ) {
                if (saving) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary)
                } else {
                    Text(if (isEdit) "Guardar cambios" else "Crear")
                }
            }
        }
    }
}

private fun fieldLabel(key: String): String = when (key) {
    "username" -> "Usuario"
    "domain" -> "Dominio"
    "password" -> "Contrasena"
    "cardHolderName" -> "Titular"
    "cardNumber" -> "Numero de tarjeta"
    "expirationDate" -> "Caducidad"
    "postalCode" -> "Codigo postal"
    "cvv" -> "CVV"
    else -> key
}

private fun shouldMask(key: String): Boolean = key in setOf("password", "cvv", "cardNumber")
