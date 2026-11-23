package com.shieldforge.app.ui.signing

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.ui.theme.AmberCaution
import com.example.ui.theme.CyberViolet
import com.example.ui.theme.ElectricBlue
import com.example.ui.theme.EmeraldVerified
import com.example.ui.theme.ObsidianVoid
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.apk.signing.SigningProfile
import com.shieldforge.app.core.storage.SigningProfileEntity
import com.shieldforge.app.ui.components.GlassPanelCard
import com.shieldforge.app.ui.components.MonoCodeText
import com.shieldforge.app.ui.components.SectionHeader
import com.shieldforge.app.ui.components.StatusPill

@Composable
fun SigningManagerScreen(
    activeProfile: SigningProfile?,
    savedProfiles: List<SigningProfileEntity>,
    onCreatePkcs12: (alias: String, pwd: String, cn: String, org: String) -> Unit,
    onImportPkcs12Uri: (Uri, String) -> Unit,
    onActivateProfile: (SigningProfileEntity, String) -> Unit,
) {
    var showCreateDialog by remember { mutableStateOf(false) }
    var pendingImportUri by remember { mutableStateOf<Uri?>(null) }
    var importPassword by remember { mutableStateOf("") }
    var unlockEntity by remember { mutableStateOf<SigningProfileEntity?>(null) }
    var unlockPassword by remember { mutableStateOf("") }

    val p12Picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> if (uri != null) pendingImportUri = uri }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(ObsidianVoid),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            SectionHeader(
                title = "Signing Manager",
                subtitle = "Dual JAR v1 + APK Signature Scheme v2 • Android Keystore & PKCS#12",
            )
        }

        // Re-signing identity disclosure
        item {
            GlassPanelCard(accentColor = AmberCaution) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Warning, contentDescription = null, tint = AmberCaution)
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = "Re-signing Notice",
                        style = MaterialTheme.typography.titleSmall,
                        color = TextPrimary,
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "Rebuilding and re-signing an APK assigns a new cryptographic signing identity unless you import your original release keystore. Android blocks in-place updates across mismatched certificates.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
            }
        }

        // Active signing key
        if (activeProfile != null) {
            item {
                GlassPanelCard(accentColor = EmeraldVerified) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Key, contentDescription = null, tint = EmeraldVerified)
                            Spacer(Modifier.width(8.dp))
                            Text(activeProfile.alias, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                        }
                        StatusPill(text = "ACTIVE SIGNER", color = EmeraldVerified)
                    }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = "${activeProfile.storageKind} • ${activeProfile.commonName} (${activeProfile.organization})",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary,
                    )
                    Spacer(Modifier.height(6.dp))
                    MonoCodeText(text = "SHA-256: ${activeProfile.sha256Fingerprint}", maxLines = 2)
                    MonoCodeText(text = "SHA-1  : ${activeProfile.sha1Fingerprint}", maxLines = 1)
                }
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    onClick = { showCreateDialog = true },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("btn_create_keystore"),
                ) {
                    Icon(Icons.Filled.Add, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("New Keystore")
                }
                OutlinedButton(
                    onClick = { p12Picker.launch(arrayOf("application/x-pkcs12", "*/*")) },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("btn_import_keystore"),
                ) {
                    Icon(Icons.Filled.UploadFile, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("Import .p12")
                }
            }
        }

        item {
            SectionHeader(title = "Configured Signing Aliases (${savedProfiles.size})")
        }

        items(savedProfiles, key = { it.id }) { entity ->
            val isActive = entity.id == activeProfile?.id
            GlassPanelCard(
                accentColor = if (isActive) ElectricBlue else CyberViolet,
                onClick = {
                    if (entity.storageKind == "ANDROID_KEYSTORE") {
                        onActivateProfile(entity, "")
                    } else {
                        unlockEntity = entity
                    }
                },
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(entity.alias, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                    StatusPill(
                        text = if (isActive) "ACTIVE" else entity.storageKind,
                        color = if (isActive) EmeraldVerified else CyberViolet,
                    )
                }
                Spacer(Modifier.height(4.dp))
                MonoCodeText(text = "SHA-256: ${entity.sha256Fingerprint.take(32)}...")
            }
        }
    }

    if (showCreateDialog) {
        var alias by remember { mutableStateOf("release_key") }
        var password by remember { mutableStateOf("") }
        var cn by remember { mutableStateOf("ShieldForge Release") }
        var org by remember { mutableStateOf("Authorized Developer") }
        AlertDialog(
            onDismissRequest = { showCreateDialog = false },
            title = { Text("Generate PKCS#12 Signing Keystore") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(value = alias, onValueChange = { alias = it }, label = { Text("Key Alias") }, singleLine = true)
                    OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text("Keystore Password") }, singleLine = true)
                    OutlinedTextField(value = cn, onValueChange = { cn = it }, label = { Text("Common Name (CN)") }, singleLine = true)
                    OutlinedTextField(value = org, onValueChange = { org = it }, label = { Text("Organization (O)") }, singleLine = true)
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onCreatePkcs12(alias.ifBlank { "release_key" }, password.ifBlank { "shieldforge" }, cn, org)
                        showCreateDialog = false
                    },
                ) { Text("Generate RSA-2048") }
            },
            dismissButton = {
                TextButton(onClick = { showCreateDialog = false }) { Text("Cancel") }
            },
        )
    }

    pendingImportUri?.let { uri ->
        AlertDialog(
            onDismissRequest = { pendingImportUri = null },
            title = { Text("Unlock Imported PKCS#12 Keystore") },
            text = {
                OutlinedTextField(
                    value = importPassword,
                    onValueChange = { importPassword = it },
                    label = { Text("Keystore Password") },
                    singleLine = true,
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onImportPkcs12Uri(uri, importPassword)
                        pendingImportUri = null
                        importPassword = ""
                    },
                ) { Text("Import") }
            },
            dismissButton = {
                TextButton(onClick = { pendingImportUri = null }) { Text("Cancel") }
            },
        )
    }

    unlockEntity?.let { ent ->
        AlertDialog(
            onDismissRequest = { unlockEntity = null },
            title = { Text("Activate '${ent.alias}'") },
            text = {
                OutlinedTextField(
                    value = unlockPassword,
                    onValueChange = { unlockPassword = it },
                    label = { Text("Keystore Password") },
                    singleLine = true,
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onActivateProfile(ent, unlockPassword)
                        unlockEntity = null
                        unlockPassword = ""
                    },
                ) { Text("Activate") }
            },
            dismissButton = {
                TextButton(onClick = { unlockEntity = null }) { Text("Cancel") }
            },
        )
    }
}
