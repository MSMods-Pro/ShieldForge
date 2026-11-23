package com.shieldforge.app.ui.importscreen

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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.ui.theme.CyberViolet
import com.example.ui.theme.ElectricBlue
import com.example.ui.theme.EmeraldVerified
import com.example.ui.theme.ObsidianVoid
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.apk.importer.SourceProjectAnalysisResult
import com.shieldforge.app.ui.components.GlassPanelCard
import com.shieldforge.app.ui.components.MonoCodeText
import com.shieldforge.app.ui.components.SectionHeader
import com.shieldforge.app.ui.components.StatusPill

@Composable
fun ImportScreen(
    isImporting: Boolean,
    isRunningApo: Boolean,
    sourceAnalysis: SourceProjectAnalysisResult?,
    onImportApkUri: (Uri) -> Unit,
    onInspectOwnApk: () -> Unit,
    onImportSourceTreeUri: (Uri) -> Unit,
    onRunSourceHardening: () -> Unit,
    onOpenWorkspace: () -> Unit,
    onViewReports: () -> Unit,
) {
    val apkPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) onImportApkUri(uri)
    }

    val treePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree(),
    ) { uri ->
        if (uri != null) onImportSourceTreeUri(uri)
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(ObsidianVoid),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            SectionHeader(
                title = "Import & Ingestion Studio",
                subtitle = "Zero-permission Storage Access Framework • Originals never overwritten",
            )
        }

        if (isImporting || isRunningApo) {
            item {
                GlassPanelCard(modifier = Modifier.fillMaxWidth(), accentColor = ElectricBlue) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.size(22.dp), strokeWidth = 2.5.dp)
                        Spacer(Modifier.width(12.dp))
                        Text(
                            text = if (isImporting) "Parsing binary APK / Gradle structure..." else "Generating Mode B hardening bundle...",
                            style = MaterialTheme.typography.titleSmall,
                            color = TextPrimary,
                        )
                    }
                }
            }
        }

        // MODE A: EXISTING APK
        item {
            GlassPanelCard(modifier = Modifier.fillMaxWidth(), accentColor = ElectricBlue) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    StatusPill(text = "MODE A • PRECOMPILED APK", color = ElectricBlue)
                    Icon(Icons.Filled.Shield, contentDescription = null, tint = ElectricBlue)
                }
                Spacer(Modifier.height(10.dp))
                Text(
                    text = "Existing APK Protection",
                    style = MaterialTheme.typography.titleLarge,
                    color = TextPrimary,
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "Imports standard & multidex APKs, parses DEX 035–041, binary AXML Manifest, resources.arsc, and native .so ABIs. Runs safe precompiled hardening + BuildGuard v1/v2 signing.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
                Spacer(Modifier.height(14.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(
                        onClick = {
                            apkPicker.launch(arrayOf("application/vnd.android.package-archive", "*/*"))
                        },
                        enabled = !isImporting,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("btn_pick_apk_saf"),
                        colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue),
                    ) {
                        Icon(Icons.Filled.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Select APK")
                    }
                    OutlinedButton(
                        onClick = onInspectOwnApk,
                        enabled = !isImporting,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("btn_import_self_apk"),
                    ) {
                        Icon(Icons.Filled.VerifiedUser, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Self-APK")
                    }
                }
            }
        }

        // MODE B: SOURCE PROJECT
        item {
            GlassPanelCard(modifier = Modifier.fillMaxWidth(), accentColor = CyberViolet) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    StatusPill(text = "MODE B • ANDROID SOURCE", color = CyberViolet)
                    Icon(Icons.Filled.Code, contentDescription = null, tint = CyberViolet)
                }
                Spacer(Modifier.height(10.dp))
                Text(
                    text = "Source Project Hardening",
                    style = MaterialTheme.typography.titleLarge,
                    color = TextPrimary,
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "Scans authorized Gradle / Kotlin / Java project trees for R8 optimization, ProGuard rules, Keystore-backed StringForgeVault, ConfigForgeStore, and IntegrityForgeGuard generation.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
                Spacer(Modifier.height(14.dp))
                FilledTonalButton(
                    onClick = { treePicker.launch(null) },
                    enabled = !isImporting,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("btn_pick_source_tree"),
                ) {
                    Icon(Icons.Filled.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Import Gradle Project Folder")
                }
            }
        }

        if (sourceAnalysis != null) {
            item {
                GlassPanelCard(modifier = Modifier.fillMaxWidth(), accentColor = EmeraldVerified) {
                    SectionHeader(
                        title = sourceAnalysis.projectName,
                        subtitle = "AppId: ${sourceAnalysis.applicationId}",
                        trailing = {
                            StatusPill(
                                text = if (sourceAnalysis.hasR8MinifyEnabled) "R8 ON" else "R8 OFF",
                                color = if (sourceAnalysis.hasR8MinifyEnabled) EmeraldVerified else CyberViolet,
                            )
                        },
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = "${sourceAnalysis.kotlinFileCount} Kotlin • ${sourceAnalysis.javaFileCount} Java • ${sourceAnalysis.xmlFileCount} XML • ${sourceAnalysis.sensitiveStringCandidates.size} string candidates",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary,
                    )
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(
                            onClick = onRunSourceHardening,
                            enabled = !isRunningApo,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("btn_generate_source_bundle"),
                        ) {
                            Icon(Icons.Filled.Build, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Generate Hardening Bundle")
                        }
                        OutlinedButton(onClick = onViewReports) {
                            Text("Reports")
                        }
                    }
                }
            }

            items(sourceAnalysis.sourceFiles.take(20), key = { it.relativePath }) { sf ->
                GlassPanelCard(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        MonoCodeText(text = sf.relativePath, color = TextPrimary, modifier = Modifier.weight(1f))
                        StatusPill(text = sf.language, color = ElectricBlue)
                    }
                    if (sf.reflectionOrJniHits.isNotEmpty()) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "Indicators: ${sf.reflectionOrJniHits.joinToString()}",
                            style = MaterialTheme.typography.bodySmall,
                            color = CyberViolet,
                        )
                    }
                }
            }
        }
    }
}
