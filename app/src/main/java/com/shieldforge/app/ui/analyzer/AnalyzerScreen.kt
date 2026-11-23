package com.shieldforge.app.ui.analyzer

import android.graphics.BitmapFactory
import android.util.Base64
import androidx.compose.foundation.Image
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.ui.theme.AmberCaution
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyberViolet
import com.example.ui.theme.ElectricBlue
import com.example.ui.theme.EmeraldVerified
import com.example.ui.theme.ObsidianVoid
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.apk.parser.ApkAnalysisResult
import com.shieldforge.app.core.common.formatByteSize
import com.shieldforge.app.ui.components.GlassPanelCard
import com.shieldforge.app.ui.components.MonoCodeText
import com.shieldforge.app.ui.components.SectionHeader
import com.shieldforge.app.ui.components.StatusPill

@Composable
fun AnalyzerScreen(
    analysis: ApkAnalysisResult?,
    onImportApkClick: () -> Unit,
    onInspectOwnApkClick: () -> Unit,
    onOpenWorkspaceClick: () -> Unit,
) {
    if (analysis == null) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(ObsidianVoid)
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                Icons.Filled.Analytics,
                contentDescription = null,
                tint = ElectricBlue,
                modifier = Modifier.size(52.dp),
            )
            Spacer(Modifier.height(14.dp))
            Text("No APK Analyzed Yet", style = MaterialTheme.typography.headlineSmall, color = TextPrimary)
            Spacer(Modifier.height(6.dp))
            Text(
                "Import an authorized APK or run a live Self-APK Audit to inspect DEX pools, AXML Manifest, ARSC resources, and signing certificates.",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
            )
            Spacer(Modifier.height(20.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(onClick = onImportApkClick, modifier = Modifier.testTag("btn_analyzer_import")) {
                    Text("Import APK")
                }
                OutlinedButton(onClick = onInspectOwnApkClick, modifier = Modifier.testTag("btn_analyzer_self")) {
                    Text("Self-APK Audit")
                }
            }
        }
        return
    }

    val decodedBitmap = remember(analysis.iconPngBytesBase64) {
        analysis.iconPngBytesBase64?.let { b64 ->
            runCatching {
                val raw = Base64.decode(b64, Base64.DEFAULT)
                BitmapFactory.decodeByteArray(raw, 0, raw.size)?.asImageBitmap()
            }.getOrNull()
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(ObsidianVoid),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            GlassPanelCard(modifier = Modifier.fillMaxWidth(), accentColor = ElectricBlue) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (decodedBitmap != null) {
                        Image(
                            bitmap = decodedBitmap,
                            contentDescription = "Analyzed APK icon",
                            modifier = Modifier
                                .size(56.dp)
                                .clip(RoundedCornerShape(14.dp)),
                        )
                        Spacer(Modifier.width(14.dp))
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = analysis.manifest.applicationLabel ?: analysis.fileName,
                            style = MaterialTheme.typography.headlineSmall,
                            color = TextPrimary,
                        )
                        MonoCodeText(text = analysis.manifest.packageName, color = ElectricBlue)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "v${analysis.manifest.versionName} (${analysis.manifest.versionCode}) • minSdk ${analysis.manifest.minSdk ?: "?"} • targetSdk ${analysis.manifest.targetSdk ?: "?"}",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary,
                        )
                    }
                }
                Spacer(Modifier.height(12.dp))
                MonoCodeText(text = "SHA-256: ${analysis.apkSha256}", maxLines = 1)
                Text(
                    text = "Archive size: ${formatByteSize(analysis.fileSizeBytes)} • ${analysis.totalZipEntries} ZIP entries",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
                Spacer(Modifier.height(14.dp))
                Button(
                    onClick = onOpenWorkspaceClick,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("btn_open_forge_workspace"),
                    colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue),
                ) {
                    Icon(Icons.Filled.Build, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Open Protection Workspace")
                }
            }
        }

        // Signing certificate report
        item {
            GlassPanelCard(
                modifier = Modifier.fillMaxWidth(),
                accentColor = if (analysis.signatureInfo.verificationPassed) EmeraldVerified else CrimsonCritical,
            ) {
                SectionHeader(
                    title = "Signing & Certificate",
                    subtitle = analysis.signatureInfo.verificationMessage,
                    trailing = {
                        StatusPill(
                            text = if (analysis.signatureInfo.isSigned) "SIGNED" else "UNSIGNED",
                            color = if (analysis.signatureInfo.isSigned) EmeraldVerified else CrimsonCritical,
                        )
                    },
                )
                analysis.signatureInfo.certificates.forEach { cert ->
                    Spacer(Modifier.height(8.dp))
                    MonoCodeText(text = "Subject: ${cert.subjectDn}", color = TextPrimary)
                    MonoCodeText(text = "SHA-256: ${cert.sha256Fingerprint}")
                    MonoCodeText(text = "Algorithm: ${cert.algorithm}")
                }
            }
        }

        // DEX Inventory
        item {
            SectionHeader(
                title = "DEX Inventory (${analysis.dexBundle.dexFiles.size})",
                subtitle = "${analysis.dexBundle.classes.size} classes • ${analysis.dexBundle.methods.size} methods • ${analysis.dexBundle.fields.size} fields",
            )
        }
        items(analysis.dexBundle.dexFiles, key = { it.fileName }) { dex ->
            GlassPanelCard(modifier = Modifier.fillMaxWidth(), accentColor = CyberViolet) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Memory, contentDescription = null, tint = CyberViolet, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(dex.fileName, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                    }
                    StatusPill(
                        text = "DEX ${dex.version}",
                        color = if (dex.isSupportedVersion) EmeraldVerified else CrimsonCritical,
                    )
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "${dex.classCount} classes • ${dex.methodCount} methods • ${dex.fieldCount} fields • ${dex.stringCount} strings • ${formatByteSize(dex.fileSizeBytes.toLong())}",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
                MonoCodeText(text = "Adler32=${dex.adler32Valid} • SHA1=${dex.sha1Valid}")
            }
        }

        // Manifest Audit Findings
        item {
            SectionHeader(
                title = "Manifest Audit",
                subtitle = "${analysis.manifest.components.size} components • ${analysis.manifest.permissions.size} permissions",
            )
        }
        if (analysis.manifest.findings.isEmpty()) {
            item {
                GlassPanelCard(modifier = Modifier.fillMaxWidth(), accentColor = EmeraldVerified) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = EmeraldVerified)
                        Spacer(Modifier.width(10.dp))
                        Text("No high-risk manifest attributes flagged.", color = TextPrimary)
                    }
                }
            }
        } else {
            items(analysis.manifest.findings, key = { it.id }) { finding ->
                val color = when (finding.severity) {
                    "HIGH" -> CrimsonCritical
                    "MEDIUM" -> AmberCaution
                    else -> ElectricBlue
                }
                GlassPanelCard(modifier = Modifier.fillMaxWidth(), accentColor = color) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Warning, contentDescription = null, tint = color, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(finding.title, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(finding.detail, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
        }

        // Native & Resource Inventory
        item {
            GlassPanelCard(modifier = Modifier.fillMaxWidth()) {
                SectionHeader(
                    title = "Resources & Native ABIs",
                    subtitle = "${analysis.resourceBundle.arsc.resourceKeyCount} ARSC keys • ${analysis.resourceBundle.nativeLibs.size} native .so",
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = analysis.resourceBundle.categoryCounts.entries.joinToString(" • ") { "${it.key}: ${it.value}" },
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
                if (analysis.resourceBundle.nativeLibs.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    analysis.resourceBundle.nativeLibs.take(8).forEach { lib ->
                        MonoCodeText(
                            text = "${lib.abi}/${lib.fileName} (${formatByteSize(lib.sizeBytes)}, ELF64=${lib.is64BitElf})",
                        )
                    }
                }
            }
        }
    }
}
