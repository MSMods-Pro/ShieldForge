package com.shieldforge.app.ui.reports

import android.content.Intent
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
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.example.ui.theme.AmberCaution
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyberViolet
import com.example.ui.theme.ElectricBlue
import com.example.ui.theme.EmeraldVerified
import com.example.ui.theme.ObsidianVoid
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.core.common.EngineExecutionState
import com.shieldforge.app.core.common.ProjectMode
import com.shieldforge.app.core.common.ProtectionReport
import com.shieldforge.app.core.common.formatByteSize
import com.shieldforge.app.core.storage.BuildHistoryEntity
import com.shieldforge.app.ui.components.GlassPanelCard
import com.shieldforge.app.ui.components.MonoCodeText
import com.shieldforge.app.ui.components.SectionHeader
import com.shieldforge.app.ui.components.StatusPill
import java.io.File

@Composable
fun ReportsScreen(
    latestReport: ProtectionReport?,
    buildHistory: List<BuildHistoryEntity>,
    onOpenHistoryReport: (BuildHistoryEntity) -> Unit,
    onExportApkUri: (Uri) -> Unit,
    onExportJsonUri: (Uri) -> Unit,
    onExportTxtUri: (Uri) -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(ObsidianVoid),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (latestReport != null) {
            item {
                ReportHeaderAndActionsCard(
                    report = latestReport,
                    onExportApkUri = onExportApkUri,
                    onExportJsonUri = onExportJsonUri,
                    onExportTxtUri = onExportTxtUri,
                )
            }
            items(latestReport.engineResults, key = { it.moduleId.name }) { res ->
                val color = when (res.state) {
                    EngineExecutionState.SUCCEEDED -> EmeraldVerified
                    EngineExecutionState.PARTIAL_WITH_WARNINGS -> AmberCaution
                    EngineExecutionState.FAILED -> CrimsonCritical
                    else -> TextSecondary
                }
                GlassPanelCard(accentColor = color) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(res.moduleId.displayName, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                        StatusPill(text = res.state.name, color = color)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(res.summary, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    res.artifactsProduced.forEach { art ->
                        MonoCodeText(text = "+ $art", color = ElectricBlue)
                    }
                    res.warnings.forEach { warn ->
                        Text("Note: $warn", style = MaterialTheme.typography.labelSmall, color = AmberCaution)
                    }
                }
            }
            latestReport.buildFingerprint?.let { fp ->
                item {
                    GlassPanelCard(accentColor = CyberViolet) {
                        SectionHeader(title = "Build Fingerprint")
                        MonoCodeText(text = "Build ID : ${fp.buildId}")
                        MonoCodeText(text = "Input    : ${fp.inputSha256}")
                        MonoCodeText(text = "Output   : ${fp.outputSha256}")
                        MonoCodeText(text = "Manifest : ${fp.manifestSha256}")
                        MonoCodeText(text = "Signer   : ${fp.signingCertSha256}")
                    }
                }
            }
        }

        item {
            SectionHeader(
                title = "Build History (${buildHistory.size})",
                subtitle = "Tap any past build to inspect its full protection report",
            )
        }
        items(buildHistory, key = { it.reportId }) { item ->
            GlassPanelCard(
                onClick = { onOpenHistoryReport(item) },
                accentColor = if (item.succeeded) EmeraldVerified else CrimsonCritical,
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(item.projectName, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                        MonoCodeText(text = "${item.packageName} • ${item.profileName}")
                        Text(
                            text = "${item.summary} • ${item.buildDurationMs} ms",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary,
                        )
                    }
                    StatusPill(
                        text = if (item.succeeded) "VERIFIED" else "FAILED",
                        color = if (item.succeeded) EmeraldVerified else CrimsonCritical,
                    )
                }
            }
        }
    }
}

@Composable
fun ReportDetailContent(
    report: ProtectionReport,
    onExportApkUri: (Uri) -> Unit,
    onExportJsonUri: (Uri) -> Unit,
    onExportTxtUri: (Uri) -> Unit,
) {
    ReportsScreen(
        latestReport = report,
        buildHistory = emptyList(),
        onOpenHistoryReport = {},
        onExportApkUri = onExportApkUri,
        onExportJsonUri = onExportJsonUri,
        onExportTxtUri = onExportTxtUri,
    )
}

@Composable
private fun ReportHeaderAndActionsCard(
    report: ProtectionReport,
    onExportApkUri: (Uri) -> Unit,
    onExportJsonUri: (Uri) -> Unit,
    onExportTxtUri: (Uri) -> Unit,
) {
    val context = LocalContext.current
    val apkExporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.android.package-archive"),
    ) { uri -> if (uri != null) onExportApkUri(uri) }
    val jsonExporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri -> if (uri != null) onExportJsonUri(uri) }
    val txtExporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri -> if (uri != null) onExportTxtUri(uri) }

    GlassPanelCard(accentColor = if (report.validationPassed) EmeraldVerified else CrimsonCritical) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.VerifiedUser,
                    contentDescription = null,
                    tint = if (report.validationPassed) EmeraldVerified else CrimsonCritical,
                )
                Spacer(Modifier.width(8.dp))
                Text(report.projectName, style = MaterialTheme.typography.titleLarge, color = TextPrimary)
            }
            StatusPill(
                text = if (report.validationPassed) "VALIDATED" else "ISSUES",
                color = if (report.validationPassed) EmeraldVerified else CrimsonCritical,
            )
        }
        Spacer(Modifier.height(6.dp))
        MonoCodeText(text = "${report.inputPackageName} • ${report.profileName} • ${report.buildDurationMs} ms")
        Text(
            text = "Output: ${formatByteSize(report.outputSizeBytes)} • ${report.signingSummary}",
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary,
        )
        Spacer(Modifier.height(10.dp))
        if (report.mode == ProjectMode.PRECOMPILED_APK && report.outputPath.isNotBlank()) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { apkExporter.launch("${report.inputPackageName}_protected.apk") },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("btn_export_protected_apk"),
                    colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue),
                ) {
                    Icon(Icons.Filled.Download, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("Export APK")
                }
                OutlinedButton(
                    onClick = {
                        val file = File(report.outputPath)
                        if (file.exists()) {
                            val uri = FileProvider.getUriForFile(
                                context,
                                "${context.packageName}.fileprovider",
                                file,
                            )
                            val share = Intent(Intent.ACTION_SEND).apply {
                                type = "application/vnd.android.package-archive"
                                putExtra(Intent.EXTRA_STREAM, uri)
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }
                            context.startActivity(Intent.createChooser(share, "Share Protected APK"))
                        }
                    },
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Filled.Share, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("Share APK")
                }
            }
            Spacer(Modifier.height(8.dp))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { jsonExporter.launch("${report.reportId}.json") },
                modifier = Modifier.weight(1f),
            ) { Text("Export JSON") }
            OutlinedButton(
                onClick = { txtExporter.launch("${report.reportId}.txt") },
                modifier = Modifier.weight(1f),
            ) { Text("Export TXT") }
        }
    }
}
