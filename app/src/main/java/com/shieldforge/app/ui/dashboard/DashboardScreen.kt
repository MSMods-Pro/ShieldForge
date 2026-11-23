package com.shieldforge.app.ui.dashboard

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.ui.theme.AmberCaution
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyanPulse
import com.example.ui.theme.CyberViolet
import com.example.ui.theme.ElectricBlue
import com.example.ui.theme.EmeraldVerified
import com.example.ui.theme.ObsidianVoid
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.core.common.formatByteSize
import com.shieldforge.app.core.storage.BuildHistoryEntity
import com.shieldforge.app.core.storage.ProjectEntity
import com.shieldforge.app.forge.registry.ProtectionRegistry
import com.shieldforge.app.ui.components.GlassPanelCard
import com.shieldforge.app.ui.components.MonoCodeText
import com.shieldforge.app.ui.components.SectionHeader
import com.shieldforge.app.ui.components.StatusPill
import com.shieldforge.app.ui.components.TelemetryStatCard

@Composable
fun DashboardScreen(
    projects: List<ProjectEntity>,
    buildHistory: List<BuildHistoryEntity>,
    hasActiveProject: Boolean,
    onProtectApkClick: () -> Unit,
    onImportSourceClick: () -> Unit,
    onAnalyzerClick: () -> Unit,
    onInspectOwnApkClick: () -> Unit,
    onDexExplorerClick: () -> Unit,
    onEnginesClick: () -> Unit,
    onSigningClick: () -> Unit,
    onBuildHistoryClick: () -> Unit,
    onReportsClick: () -> Unit,
    onSettingsClick: () -> Unit,
    onOpenRecentProject: (ProjectEntity) -> Unit,
) {
    val protectedCount = buildHistory.count { it.succeeded }
    val failedCount = buildHistory.count { !it.succeeded }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .background(ObsidianVoid),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            // Hero Workstation Banner
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(20.dp)),
            ) {
                Image(
                    painter = painterResource(id = R.drawable.img_hero_forge),
                    contentDescription = "ShieldForge workstation banner",
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.matchParentSize(),
                )
                Box(
                    modifier = Modifier
                        .matchParentSize()
                        .background(
                            Brush.horizontalGradient(
                                listOf(
                                    ObsidianVoid.copy(alpha = 0.92f),
                                    ObsidianVoid.copy(alpha = 0.72f),
                                ),
                            ),
                        ),
                )
                Column(modifier = Modifier.padding(20.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        StatusPill(text = "FORGE-X ARCHITECTURE", color = ElectricBlue)
                        Spacer(Modifier.width(8.dp))
                        StatusPill(text = "APO ACTIVE", color = CyberViolet)
                    }
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = "ShieldForge Studio",
                        style = MaterialTheme.typography.displaySmall,
                        color = TextPrimary,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "Adaptive multi-layer APK inspection, selective DEX hardening, and verified Keystore signing.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary,
                    )
                    Spacer(Modifier.height(16.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Button(
                            onClick = onProtectApkClick,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("btn_protect_apk"),
                            colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue),
                        ) {
                            Icon(Icons.Filled.Shield, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Protect APK")
                        }
                        FilledTonalButton(
                            onClick = onImportSourceClick,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("btn_import_source"),
                        ) {
                            Icon(Icons.Filled.Code, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Source Mode")
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        OutlinedButton(
                            onClick = onAnalyzerClick,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("btn_apk_analyzer"),
                        ) {
                            Icon(Icons.Filled.Analytics, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("APK Analyzer")
                        }
                        OutlinedButton(
                            onClick = onInspectOwnApkClick,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("btn_self_audit"),
                        ) {
                            Icon(Icons.Filled.VerifiedUser, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Self-APK Audit")
                        }
                    }
                }
            }
        }

        // Telemetry KPIs
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                TelemetryStatCard(
                    label = "TOTAL PROJECTS",
                    value = projects.size.toString(),
                    icon = Icons.Filled.FolderOpen,
                    accent = ElectricBlue,
                    modifier = Modifier.weight(1f),
                )
                TelemetryStatCard(
                    label = "PROTECTED APKS",
                    value = protectedCount.toString(),
                    icon = Icons.Filled.VerifiedUser,
                    accent = EmeraldVerified,
                    modifier = Modifier.weight(1f),
                )
            }
            Spacer(Modifier.height(10.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                TelemetryStatCard(
                    label = "FAILED BUILDS",
                    value = failedCount.toString(),
                    icon = Icons.Filled.Warning,
                    accent = if (failedCount > 0) CrimsonCritical else AmberCaution,
                    modifier = Modifier.weight(1f),
                )
                TelemetryStatCard(
                    label = "FORGE ENGINES",
                    value = ProtectionRegistry.engines.size.toString(),
                    icon = Icons.Filled.Memory,
                    accent = CyberViolet,
                    modifier = Modifier.weight(1f),
                )
            }
        }

        // Secondary Workstation Actions
        item {
            SectionHeader(
                title = "Workstation Modules",
                subtitle = if (hasActiveProject) "Workspace loaded & ready" else "Select an APK or jump to a module",
            )
            Spacer(Modifier.height(8.dp))
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    QuickActionTile(
                        title = "DEX Explorer",
                        subtitle = "Multidex & trees",
                        icon = Icons.Filled.Memory,
                        accent = CyanPulse,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("tile_dex_explorer"),
                        onClick = onDexExplorerClick,
                    )
                    QuickActionTile(
                        title = "Protection Engines",
                        subtitle = "7 FORGE-X modules",
                        icon = Icons.Filled.Build,
                        accent = ElectricBlue,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("tile_engines"),
                        onClick = onEnginesClick,
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    QuickActionTile(
                        title = "Signing Manager",
                        subtitle = "Keystore & certs",
                        icon = Icons.Filled.Key,
                        accent = CyberViolet,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("tile_signing"),
                        onClick = onSigningClick,
                    )
                    QuickActionTile(
                        title = "Build History",
                        subtitle = "${buildHistory.size} builds logged",
                        icon = Icons.Filled.History,
                        accent = EmeraldVerified,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("tile_history"),
                        onClick = onBuildHistoryClick,
                    )
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    QuickActionTile(
                        title = "Security Reports",
                        subtitle = "JSON & TXT exports",
                        icon = Icons.Filled.Description,
                        accent = AmberCaution,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("tile_reports"),
                        onClick = onReportsClick,
                    )
                    QuickActionTile(
                        title = "Settings",
                        subtitle = "APO & Registry",
                        icon = Icons.Filled.Settings,
                        accent = TextSecondary,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("tile_settings"),
                        onClick = onSettingsClick,
                    )
                }
            }
        }

        // Recent Projects
        item {
            SectionHeader(
                title = "Recent Projects",
                subtitle = "Cached APK workspaces (originals never modified)",
            )
        }

        if (projects.isEmpty()) {
            item {
                GlassPanelCard(modifier = Modifier.fillMaxWidth()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Image(
                            painter = painterResource(id = R.drawable.img_empty_vault),
                            contentDescription = "No imported projects yet",
                            contentScale = ContentScale.Crop,
                            modifier = Modifier
                                .size(78.dp)
                                .clip(RoundedCornerShape(12.dp)),
                        )
                        Spacer(Modifier.width(14.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "No APK Workspace Loaded",
                                style = MaterialTheme.typography.titleMedium,
                                color = TextPrimary,
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = "Import an authorized APK via Storage Access Framework or run Self-APK Audit to inspect real DEX, Manifest, and ARSC structures.",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextSecondary,
                            )
                        }
                    }
                }
            }
        } else {
            items(projects.take(6), key = { it.projectId }) { proj ->
                GlassPanelCard(
                    onClick = { onOpenRecentProject(proj) },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = proj.name,
                                style = MaterialTheme.typography.titleMedium,
                                color = TextPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            MonoCodeText(text = proj.packageName)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text = "${proj.dexCount} DEX • ${proj.classCount} classes • ${formatByteSize(proj.fileSizeBytes)}",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextSecondary,
                            )
                        }
                        StatusPill(text = proj.lastProfileName, color = ElectricBlue)
                    }
                }
            }
        }
    }
}

@Composable
private fun QuickActionTile(
    title: String,
    subtitle: String,
    icon: ImageVector,
    accent: Color,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    GlassPanelCard(
        modifier = modifier,
        accentColor = accent.copy(alpha = 0.4f),
        onClick = onClick,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(accent.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, contentDescription = title, tint = accent, modifier = Modifier.size(20.dp))
            }
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    color = TextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}
