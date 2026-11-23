package com.shieldforge.app.ui.protection

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.example.ui.theme.AmberCaution
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyberViolet
import com.example.ui.theme.ElectricBlue
import com.example.ui.theme.EmeraldVerified
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.apk.parser.ApkAnalysisResult
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.forge.dependency.DependencyPlanSummary
import com.shieldforge.app.forge.profiles.ProtectionEngineOptions
import com.shieldforge.app.forge.profiles.ProtectionProfile
import com.shieldforge.app.forge.profiles.ProtectionProfilesCatalog
import com.shieldforge.app.forge.registry.ProtectionRegistry
import com.shieldforge.app.ui.components.GlassPanelCard
import com.shieldforge.app.ui.components.MonoCodeText
import com.shieldforge.app.ui.components.SectionHeader
import com.shieldforge.app.ui.components.StatusPill

@Composable
fun ProtectionConfigTab(
    analysis: ApkAnalysisResult?,
    activeProfile: ProtectionProfile,
    dependencyPlan: DependencyPlanSummary?,
    onSelectProfile: (ProtectionProfile) -> Unit,
    onToggleModule: (ProtectionModuleId) -> Unit,
    onUpdateOptions: ((ProtectionEngineOptions) -> ProtectionEngineOptions) -> Unit,
    onSetPerDexModules: (String, Set<ProtectionModuleId>) -> Unit,
    onExportProfileJson: (Uri) -> Unit,
    onImportProfileJson: (Uri) -> Unit,
) {
    val exportProfileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri -> if (uri != null) onExportProfileJson(uri) }

    val importProfileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> if (uri != null) onImportProfileJson(uri) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            SectionHeader(
                title = "Protection Profiles (9 Presets)",
                subtitle = "Active: ${activeProfile.name}",
            )
            Spacer(Modifier.height(6.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                ProtectionProfilesCatalog.builtInProfiles.forEach { preset ->
                    FilterChip(
                        selected = activeProfile.id == preset.id,
                        onClick = { onSelectProfile(preset) },
                        label = { Text(preset.name) },
                        modifier = Modifier.testTag("profile_chip_${preset.id}"),
                    )
                }
            }
            Spacer(Modifier.height(6.dp))
            Text(activeProfile.description, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { exportProfileLauncher.launch("shieldforge_profile.json") },
                    modifier = Modifier.weight(1f),
                ) { Text("Export Profile") }
                OutlinedButton(
                    onClick = { importProfileLauncher.launch(arrayOf("application/json", "*/*")) },
                    modifier = Modifier.weight(1f),
                ) { Text("Import Profile") }
            }
        }

        // Engine Switches
        item {
            SectionHeader(
                title = "FORGE-X Protection Engines",
                subtitle = "Every switch connects directly to APO execution",
            )
        }
        items(ProtectionModuleId.entries, key = { it.name }) { mod ->
            val enabled = mod in activeProfile.enabledModules
            val desc = ProtectionRegistry.descriptorFor(mod)
            GlassPanelCard(accentColor = if (enabled) ElectricBlue else com.example.ui.theme.GraphiteBorder) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            StatusPill(text = mod.codeName, color = CyberViolet)
                            Spacer(Modifier.width(8.dp))
                            Text(mod.displayName, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(mod.summary, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "Mode A: ${desc.modeACapabilities.first()}",
                            style = MaterialTheme.typography.labelSmall,
                            color = EmeraldVerified,
                        )
                    }
                    Switch(
                        checked = enabled,
                        onCheckedChange = { onToggleModule(mod) },
                        modifier = Modifier.testTag("switch_engine_${mod.name.lowercase()}"),
                    )
                }
            }
        }

        // Fine-grained engine options
        item {
            GlassPanelCard {
                SectionHeader(title = "Engine Execution Parameters")
                Spacer(Modifier.height(6.dp))
                OptionToggleRow(
                    title = "Strip DEX SourceFile Metadata",
                    checked = activeProfile.options.stripDexSourceFileMetadata,
                    onCheckedChange = { v -> onUpdateOptions { it.copy(stripDexSourceFileMetadata = v) } },
                )
                OptionToggleRow(
                    title = "Seal Sensitive Strings to AES-256-GCM Vault",
                    checked = activeProfile.options.sealSensitiveStringsToVault,
                    onCheckedChange = { v -> onUpdateOptions { it.copy(sealSensitiveStringsToVault = v) } },
                )
                OptionToggleRow(
                    title = "Harden android:debuggable=false (AXML)",
                    checked = activeProfile.options.hardenManifestDebuggable,
                    onCheckedChange = { v -> onUpdateOptions { it.copy(hardenManifestDebuggable = v) } },
                )
                OptionToggleRow(
                    title = "Harden android:allowBackup=false (AXML)",
                    checked = activeProfile.options.hardenManifestAllowBackup,
                    onCheckedChange = { v -> onUpdateOptions { it.copy(hardenManifestAllowBackup = v) } },
                )
                OptionToggleRow(
                    title = "Strip Safe Build Metadata (.kotlin_builtins)",
                    checked = activeProfile.options.stripBuildMetadataEntries,
                    onCheckedChange = { v -> onUpdateOptions { it.copy(stripBuildMetadataEntries = v) } },
                )
                OptionToggleRow(
                    title = "Seal Selected Config Assets (ConfigForge)",
                    checked = activeProfile.options.encryptSelectedConfigAssets,
                    onCheckedChange = { v -> onUpdateOptions { it.copy(encryptSelectedConfigAssets = v) } },
                )
                OptionToggleRow(
                    title = "Embed Signed Integrity Manifest",
                    checked = activeProfile.options.embedIntegrityManifest,
                    onCheckedChange = { v -> onUpdateOptions { it.copy(embedIntegrityManifest = v) } },
                )
            }
        }

        // Per-DEX configuration
        if (analysis != null && analysis.dexBundle.dexFiles.isNotEmpty()) {
            item {
                SectionHeader(
                    title = "Per-DEX Profiles",
                    subtitle = "Configure StringForge / DEXForge independently per DEX",
                )
            }
            items(analysis.dexBundle.dexFiles, key = { "cfg_${it.fileName}" }) { dex ->
                val currentSet = activeProfile.perDexOverrides[dex.fileName] ?: activeProfile.enabledModules
                GlassPanelCard {
                    Text(dex.fileName, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                    Spacer(Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf(
                            ProtectionModuleId.STRING_FORGE,
                            ProtectionModuleId.DEX_FORGE,
                            ProtectionModuleId.INTEGRITY_FORGE,
                        ).forEach { mod ->
                            val isOn = mod in currentSet
                            FilterChip(
                                selected = isOn,
                                onClick = {
                                    val next = if (isOn) currentSet - mod else currentSet + mod
                                    onSetPerDexModules(dex.fileName, next)
                                },
                                label = { Text(mod.displayName) },
                            )
                        }
                    }
                }
            }
        }

        // Dependency conflicts
        if (dependencyPlan != null && dependencyPlan.conflicts.isNotEmpty()) {
            item {
                SectionHeader(
                    title = "APO Dependency & Compatibility Alerts",
                    subtitle = "${dependencyPlan.conflicts.size} item(s) analyzed",
                )
            }
            items(dependencyPlan.conflicts, key = { it.id }) { conflict ->
                val color = if (conflict.severity == "BLOCKING") CrimsonCritical else AmberCaution
                GlassPanelCard(accentColor = color) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(conflict.componentLabel, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                        StatusPill(text = conflict.severity, color = color)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(conflict.reason, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    Spacer(Modifier.height(2.dp))
                    MonoCodeText(text = "APO: ${conflict.resolution}", color = EmeraldVerified, maxLines = 3)
                }
            }
        }
    }
}

@Composable
private fun OptionToggleRow(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyMedium,
            color = TextPrimary,
            modifier = Modifier.weight(1f),
        )
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
