package com.shieldforge.app.ui.workspace

import android.net.Uri
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
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
import com.example.ui.theme.GraphiteBorder
import com.example.ui.theme.GraphiteLow
import com.example.ui.theme.ObsidianSurface
import com.example.ui.theme.ObsidianVoid
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.apk.parser.ApkAnalysisResult
import com.shieldforge.app.core.common.ComponentType
import com.shieldforge.app.core.common.LogLevel
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.core.common.WorkspaceTab
import com.shieldforge.app.core.common.formatByteSize
import com.shieldforge.app.ui.analyzer.AnalyzerScreen
import com.shieldforge.app.ui.components.CompatibilityBadge
import com.shieldforge.app.ui.components.ComponentStatusBadge
import com.shieldforge.app.ui.components.GlassPanelCard
import com.shieldforge.app.ui.components.MonoCodeText
import com.shieldforge.app.ui.components.SectionHeader
import com.shieldforge.app.ui.components.StatusPill
import com.shieldforge.app.ui.explorer.ClassExplorerTab
import com.shieldforge.app.ui.explorer.DexFilesExplorerTab
import com.shieldforge.app.ui.explorer.ExplorerSearchAndSelectionBar
import com.shieldforge.app.ui.explorer.FieldExplorerTab
import com.shieldforge.app.ui.explorer.MethodExplorerTab
import com.shieldforge.app.ui.explorer.PackageExplorerTab
import com.shieldforge.app.ui.explorer.StringExplorerTab
import com.shieldforge.app.ui.protection.ProtectionConfigTab
import com.shieldforge.app.ui.reports.ReportDetailContent
import com.shieldforge.app.ui.state.ShieldForgeUiState

@Composable
fun WorkspaceScreen(
    state: ShieldForgeUiState,
    onSelectTab: (WorkspaceTab) -> Unit,
    onImportApkClick: () -> Unit,
    onInspectOwnApkClick: () -> Unit,
    onSearchChange: (String) -> Unit,
    onFilterChange: (com.shieldforge.app.core.common.ExplorerFilterMode) -> Unit,
    onDexFilterChange: (String?) -> Unit,
    onToggleSelection: (ComponentType, String) -> Unit,
    onSelectAllInPackage: (String) -> Unit,
    onExcludePackage: (String) -> Unit,
    onBatchSelection: (String) -> Unit,
    onSaveSelectionSnapshot: (String) -> Unit,
    onLoadSelectionSnapshot: (com.shieldforge.app.core.common.SelectionProfileExport) -> Unit,
    onExportSelectionJson: (Uri) -> Unit,
    onImportSelectionJson: (Uri) -> Unit,
    onSaveOverride: (com.shieldforge.app.core.common.ComponentProtectionOverride) -> Unit,
    onSelectProfile: (com.shieldforge.app.forge.profiles.ProtectionProfile) -> Unit,
    onToggleModule: (ProtectionModuleId) -> Unit,
    onUpdateOptions: ((com.shieldforge.app.forge.profiles.ProtectionEngineOptions) -> com.shieldforge.app.forge.profiles.ProtectionEngineOptions) -> Unit,
    onSetPerDexModules: (String, Set<ProtectionModuleId>) -> Unit,
    onExportProfileJson: (Uri) -> Unit,
    onImportProfileJson: (Uri) -> Unit,
    onRunApoPipeline: () -> Unit,
    onExportOutputApk: (Uri) -> Unit,
    onExportReportJson: (Uri) -> Unit,
    onExportReportTxt: (Uri) -> Unit,
) {
    val analysis = state.currentApkAnalysis

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(ObsidianVoid),
    ) {
        ScrollableTabRow(
            selectedTabIndex = state.activeWorkspaceTab.ordinal,
            containerColor = ObsidianSurface,
            contentColor = ElectricBlue,
            edgePadding = 12.dp,
        ) {
            WorkspaceTab.entries.forEach { tab ->
                Tab(
                    selected = state.activeWorkspaceTab == tab,
                    onClick = { onSelectTab(tab) },
                    text = { Text(tab.shortTitle, style = MaterialTheme.typography.labelLarge) },
                    modifier = Modifier.testTag("tab_${tab.name.lowercase()}"),
                )
            }
        }

        val showExplorerFilter = state.activeWorkspaceTab in setOf(
            WorkspaceTab.PACKAGE_EXPLORER,
            WorkspaceTab.CLASS_EXPLORER,
            WorkspaceTab.METHOD_EXPLORER,
            WorkspaceTab.FIELD_EXPLORER,
            WorkspaceTab.STRING_EXPLORER,
        )

        if (analysis != null && showExplorerFilter) {
            ExplorerSearchAndSelectionBar(
                searchQuery = state.explorerSearchQuery,
                filterMode = state.explorerFilter,
                dexNames = analysis.dexBundle.dexFiles.map { it.fileName },
                selectedDexFilter = state.explorerDexFilter,
                savedSnapshots = state.savedSelectionProfiles,
                onSearchChange = onSearchChange,
                onFilterChange = onFilterChange,
                onDexFilterChange = onDexFilterChange,
                onBatchAction = onBatchSelection,
                onSaveSnapshot = onSaveSelectionSnapshot,
                onLoadSnapshot = onLoadSelectionSnapshot,
                onExportJsonUri = onExportSelectionJson,
                onImportJsonUri = onImportSelectionJson,
            )
        }

        Box(modifier = Modifier.weight(1f)) {
            when (state.activeWorkspaceTab) {
                WorkspaceTab.OVERVIEW -> AnalyzerScreen(
                    analysis = analysis,
                    onImportApkClick = onImportApkClick,
                    onInspectOwnApkClick = onInspectOwnApkClick,
                    onOpenWorkspaceClick = { onSelectTab(WorkspaceTab.DEX_EXPLORER) },
                )
                WorkspaceTab.DEX_EXPLORER -> {
                    if (analysis == null) EmptyWorkspacePrompt(onImportApkClick, onInspectOwnApkClick)
                    else DexFilesExplorerTab(
                        analysis = analysis,
                        selection = state.selection,
                        onToggleDex = { onToggleSelection(ComponentType.DEX_FILE, it) },
                    )
                }
                WorkspaceTab.PACKAGE_EXPLORER -> {
                    if (analysis == null) EmptyWorkspacePrompt(onImportApkClick, onInspectOwnApkClick)
                    else PackageExplorerTab(
                        analysis = analysis,
                        selection = state.selection,
                        searchQuery = state.explorerSearchQuery,
                        dexFilter = state.explorerDexFilter,
                        onTogglePackage = { onToggleSelection(ComponentType.PACKAGE, it) },
                        onSelectAllInPackage = onSelectAllInPackage,
                        onExcludePackage = onExcludePackage,
                        onInspectClass = { onSelectTab(WorkspaceTab.CLASS_EXPLORER) },
                    )
                }
                WorkspaceTab.CLASS_EXPLORER -> {
                    if (analysis == null) EmptyWorkspacePrompt(onImportApkClick, onInspectOwnApkClick)
                    else ClassExplorerTab(
                        analysis = analysis,
                        selection = state.selection,
                        searchQuery = state.explorerSearchQuery,
                        filterMode = state.explorerFilter,
                        dexFilter = state.explorerDexFilter,
                        onToggleClass = { onToggleSelection(ComponentType.CLASS, it) },
                        onSaveOverride = onSaveOverride,
                    )
                }
                WorkspaceTab.METHOD_EXPLORER -> {
                    if (analysis == null) EmptyWorkspacePrompt(onImportApkClick, onInspectOwnApkClick)
                    else MethodExplorerTab(
                        analysis = analysis,
                        selection = state.selection,
                        searchQuery = state.explorerSearchQuery,
                        filterMode = state.explorerFilter,
                        dexFilter = state.explorerDexFilter,
                        onToggleMethod = { onToggleSelection(ComponentType.METHOD, it) },
                    )
                }
                WorkspaceTab.FIELD_EXPLORER -> {
                    if (analysis == null) EmptyWorkspacePrompt(onImportApkClick, onInspectOwnApkClick)
                    else FieldExplorerTab(
                        analysis = analysis,
                        selection = state.selection,
                        searchQuery = state.explorerSearchQuery,
                        filterMode = state.explorerFilter,
                        dexFilter = state.explorerDexFilter,
                        onToggleField = { onToggleSelection(ComponentType.FIELD, it) },
                    )
                }
                WorkspaceTab.STRING_EXPLORER -> {
                    if (analysis == null) EmptyWorkspacePrompt(onImportApkClick, onInspectOwnApkClick)
                    else StringExplorerTab(
                        analysis = analysis,
                        selection = state.selection,
                        searchQuery = state.explorerSearchQuery,
                        filterMode = state.explorerFilter,
                        dexFilter = state.explorerDexFilter,
                        onToggleString = { onToggleSelection(ComponentType.STRING, it) },
                    )
                }
                WorkspaceTab.MANIFEST_EXPLORER -> {
                    if (analysis == null) EmptyWorkspacePrompt(onImportApkClick, onInspectOwnApkClick)
                    else ManifestExplorerTab(
                        analysis = analysis,
                        selectedItems = state.selection.selectedManifestItems,
                        onToggleItem = { onToggleSelection(ComponentType.MANIFEST_COMPONENT, it) },
                    )
                }
                WorkspaceTab.RESOURCE_EXPLORER -> {
                    if (analysis == null) EmptyWorkspacePrompt(onImportApkClick, onInspectOwnApkClick)
                    else ResourceExplorerTab(
                        analysis = analysis,
                        selectedResources = state.selection.selectedResources,
                        onToggleResource = { onToggleSelection(ComponentType.RESOURCE, it) },
                    )
                }
                WorkspaceTab.PROTECTION_CONFIG -> ProtectionConfigTab(
                    analysis = analysis,
                    activeProfile = state.activeProfile,
                    dependencyPlan = state.dependencyPlan,
                    onSelectProfile = onSelectProfile,
                    onToggleModule = onToggleModule,
                    onUpdateOptions = onUpdateOptions,
                    onSetPerDexModules = onSetPerDexModules,
                    onExportProfileJson = onExportProfileJson,
                    onImportProfileJson = onImportProfileJson,
                )
                WorkspaceTab.PROCESSING_LOGS -> ProcessingLogsTab(state = state)
                WorkspaceTab.FINAL_REPORT -> {
                    if (state.latestReport != null) {
                        ReportDetailContent(
                            report = state.latestReport,
                            onExportApkUri = onExportOutputApk,
                            onExportJsonUri = onExportReportJson,
                            onExportTxtUri = onExportReportTxt,
                        )
                    } else {
                        Column(
                            modifier = Modifier.fillMaxSize().padding(24.dp),
                            verticalArrangement = Arrangement.Center,
                            horizontalAlignment = Alignment.CenterHorizontally,
                        ) {
                            Text("No Build Report Generated Yet", style = MaterialTheme.typography.titleLarge, color = TextPrimary)
                            Spacer(Modifier.height(6.dp))
                            Text(
                                "Configure components and tap Execute FORGE-X below to build, sign, and validate.",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextSecondary,
                            )
                        }
                    }
                }
            }
        }

        // Persistent Selection Summary & Execute Bar
        if (analysis != null) {
            HorizontalDivider(color = GraphiteBorder)
            Surface(color = GraphiteLow, modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "${state.selection.totalSelectedCount} selected • ${state.activeProfile.enabledModules.size} engines",
                            style = MaterialTheme.typography.titleSmall,
                            color = TextPrimary,
                        )
                        Text(
                            text = "${state.activeProfile.name} • Signer: ${state.activeSigningProfile?.alias ?: "None"}",
                            style = MaterialTheme.typography.labelSmall,
                            color = TextSecondary,
                        )
                    }
                    Button(
                        onClick = onRunApoPipeline,
                        enabled = !state.isRunningApo,
                        modifier = Modifier.testTag("btn_execute_forge_x"),
                        colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue),
                    ) {
                        if (state.isRunningApo) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                                color = TextPrimary,
                            )
                        } else {
                            Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(18.dp))
                        }
                        Spacer(Modifier.width(6.dp))
                        Text(if (state.isRunningApo) "Building..." else "Execute FORGE-X")
                    }
                }
            }
        }
    }
}

@Composable
private fun EmptyWorkspacePrompt(
    onImportApk: () -> Unit,
    onSelfAudit: () -> Unit,
) {
    AnalyzerScreen(
        analysis = null,
        onImportApkClick = onImportApk,
        onInspectOwnApkClick = onSelfAudit,
        onOpenWorkspaceClick = {},
    )
}

@Composable
private fun ManifestExplorerTab(
    analysis: ApkAnalysisResult,
    selectedItems: Set<String>,
    onToggleItem: (String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            GlassPanelCard(accentColor = ElectricBlue) {
                SectionHeader(
                    title = "Manifest Integrity & Flags",
                    subtitle = "SHA-256: ${analysis.manifest.manifestSha256.take(24)}...",
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "debuggable=${analysis.manifest.isDebuggable} • allowBackup=${analysis.manifest.allowBackup ?: "default"} • cleartext=${analysis.manifest.usesCleartextTraffic ?: "default"}",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
            }
        }
        item {
            SectionHeader(
                title = "Declared Components (${analysis.manifest.components.size})",
                subtitle = "Preserved during transformation to prevent broken entry points",
            )
        }
        items(analysis.manifest.components, key = { "${it.type}:${it.name}" }) { comp ->
            val id = "MAN:${comp.type}:${comp.name}"
            val checked = id in selectedItems
            GlassPanelCard(onClick = { onToggleItem(id) }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = checked, onCheckedChange = { onToggleItem(id) })
                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            StatusPill(text = comp.type, color = CyberViolet)
                            StatusPill(
                                text = if (comp.exported == true) "EXPORTED" else "INTERNAL",
                                color = if (comp.exported == true) AmberCaution else EmeraldVerified,
                            )
                        }
                        Spacer(Modifier.height(4.dp))
                        MonoCodeText(text = comp.name, color = TextPrimary)
                        if (comp.intentActions.isNotEmpty()) {
                            MonoCodeText(text = "Actions: ${comp.intentActions.joinToString()}")
                        }
                    }
                }
            }
        }
        item {
            SectionHeader(title = "Permissions (${analysis.manifest.permissions.size})")
        }
        items(analysis.manifest.permissions, key = { it }) { perm ->
            val id = "PERM:$perm"
            GlassPanelCard(onClick = { onToggleItem(id) }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = id in selectedItems, onCheckedChange = { onToggleItem(id) })
                    MonoCodeText(text = perm, color = TextPrimary)
                }
            }
        }
    }
}

@Composable
private fun ResourceExplorerTab(
    analysis: ApkAnalysisResult,
    selectedResources: Set<String>,
    onToggleResource: (String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            GlassPanelCard(accentColor = CyberViolet) {
                SectionHeader(
                    title = "resources.arsc Summary",
                    subtitle = "Valid=${analysis.resourceBundle.arsc.isValidArsc} • ${analysis.resourceBundle.arsc.resourceKeyCount} resource keys",
                )
                if (analysis.resourceBundle.arsc.resourceTypeNames.isNotEmpty()) {
                    MonoCodeText(
                        text = "Types: ${analysis.resourceBundle.arsc.resourceTypeNames.joinToString()}",
                    )
                }
            }
        }
        items(analysis.resourceBundle.entries.take(300), key = { it.id }) { res ->
            val checked = res.id in selectedResources
            GlassPanelCard(onClick = { onToggleResource(res.id) }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = checked, onCheckedChange = { onToggleResource(res.id) })
                    Column(modifier = Modifier.weight(1f)) {
                        MonoCodeText(text = res.path, color = TextPrimary, maxLines = 1)
                        Spacer(Modifier.height(4.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            StatusPill(text = res.category.label, color = ElectricBlue)
                            StatusPill(text = formatByteSize(res.sizeBytes), color = CyberViolet)
                            ComponentStatusBadge(res.status)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ProcessingLogsTab(state: ShieldForgeUiState) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            SectionHeader(
                title = "APO 18-Stage Pipeline",
                subtitle = if (state.isRunningApo) "Orchestrating protection engines..." else "Pipeline status",
            )
        }
        items(state.apoSteps, key = { it.index }) { step ->
            val icon = when {
                step.failed -> Icons.Filled.Error
                step.completed -> Icons.Filled.CheckCircle
                else -> Icons.Filled.RadioButtonUnchecked
            }
            val tint = when {
                step.failed -> CrimsonCritical
                step.completed -> EmeraldVerified
                step.active -> ElectricBlue
                else -> TextMuted
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (step.active) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Icon(icon, contentDescription = step.title, tint = tint, modifier = Modifier.size(18.dp))
                }
                Spacer(Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(step.title, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                    if (step.detail.isNotBlank()) {
                        Text(step.detail, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                }
            }
        }
        item {
            Spacer(Modifier.height(8.dp))
            SectionHeader(title = "Execution Log Stream (${state.logs.size})")
        }
        items(state.logs) { log ->
            val color = when (log.level) {
                LogLevel.ERROR -> CrimsonCritical
                LogLevel.WARN -> AmberCaution
                LogLevel.VERIFIED -> EmeraldVerified
                LogLevel.STAGE -> ElectricBlue
                LogLevel.INFO -> TextSecondary
            }
            MonoCodeText(text = "[${log.stage}] ${log.message}", color = color, maxLines = 3)
        }
    }
}
