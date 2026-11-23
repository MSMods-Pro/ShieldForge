package com.shieldforge.app.ui.explorer

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
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
import com.example.ui.theme.CrimsonCritical
import com.example.ui.theme.CyberViolet
import com.example.ui.theme.ElectricBlue
import com.example.ui.theme.EmeraldVerified
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.apk.dex.DexClassItem
import com.shieldforge.app.apk.dex.StringSensitivity
import com.shieldforge.app.apk.parser.ApkAnalysisResult
import com.shieldforge.app.core.common.CompatibilityState
import com.shieldforge.app.core.common.ComponentProtectionOverride
import com.shieldforge.app.core.common.ComponentType
import com.shieldforge.app.core.common.ExplorerFilterMode
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.core.common.SelectionProfileExport
import com.shieldforge.app.core.common.SelectionStateSnapshot
import com.shieldforge.app.core.common.formatByteSize
import com.shieldforge.app.ui.components.CompatibilityBadge
import com.shieldforge.app.ui.components.ComponentStatusBadge
import com.shieldforge.app.ui.components.GlassPanelCard
import com.shieldforge.app.ui.components.MonoCodeText
import com.shieldforge.app.ui.components.StatusPill

@Composable
fun ExplorerSearchAndSelectionBar(
    searchQuery: String,
    filterMode: ExplorerFilterMode,
    dexNames: List<String>,
    selectedDexFilter: String?,
    savedSnapshots: List<SelectionProfileExport>,
    onSearchChange: (String) -> Unit,
    onFilterChange: (ExplorerFilterMode) -> Unit,
    onDexFilterChange: (String?) -> Unit,
    onBatchAction: (String) -> Unit,
    onSaveSnapshot: (String) -> Unit,
    onLoadSnapshot: (SelectionProfileExport) -> Unit,
    onExportJsonUri: (Uri) -> Unit,
    onImportJsonUri: (Uri) -> Unit,
) {
    var showSelectionMenu by remember { mutableStateOf(false) }
    var snapshotName by remember { mutableStateOf("") }
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri -> if (uri != null) onExportJsonUri(uri) }
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> if (uri != null) onImportJsonUri(uri) }

    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = onSearchChange,
                placeholder = { Text("Search DEX, package, class, method, field, string...") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                modifier = Modifier
                    .weight(1f)
                    .testTag("explorer_search_input"),
            )
            Spacer(Modifier.width(8.dp))
            IconButton(
                onClick = { showSelectionMenu = true },
                modifier = Modifier.testTag("btn_selection_manager"),
            ) {
                Icon(Icons.Filled.Tune, contentDescription = "Selection Management", tint = ElectricBlue)
            }
        }
        Spacer(Modifier.height(6.dp))
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            ExplorerFilterMode.entries.forEach { mode ->
                FilterChip(
                    selected = filterMode == mode,
                    onClick = { onFilterChange(mode) },
                    label = { Text(mode.label) },
                )
            }
            if (dexNames.size > 1) {
                FilterChip(
                    selected = selectedDexFilter == null,
                    onClick = { onDexFilterChange(null) },
                    label = { Text("All DEX") },
                )
                dexNames.forEach { dName ->
                    FilterChip(
                        selected = selectedDexFilter == dName,
                        onClick = { onDexFilterChange(dName) },
                        label = { Text(dName) },
                    )
                }
            }
        }
    }

    if (showSelectionMenu) {
        AlertDialog(
            onDismissRequest = { showSelectionMenu = false },
            title = { Text("Selection Management") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { onBatchAction("SELECT_ALL_DEX"); showSelectionMenu = false },
                            modifier = Modifier.weight(1f),
                        ) { Text("All DEX") }
                        OutlinedButton(
                            onClick = { onBatchAction("SELECT_ALL_PACKAGES"); showSelectionMenu = false },
                            modifier = Modifier.weight(1f),
                        ) { Text("All Pkg") }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { onBatchAction("INVERT_CLASSES"); showSelectionMenu = false },
                            modifier = Modifier.weight(1f),
                        ) { Text("Invert Cls") }
                        OutlinedButton(
                            onClick = { onBatchAction("SELECT_NONE"); showSelectionMenu = false },
                            modifier = Modifier.weight(1f),
                        ) { Text("Select None") }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { onBatchAction("SELECT_SENSITIVE_STRINGS"); showSelectionMenu = false },
                            modifier = Modifier.weight(1f),
                        ) { Text("Sensitive Str") }
                        OutlinedButton(
                            onClick = { onBatchAction("SELECT_SAFE_META_RES"); showSelectionMenu = false },
                            modifier = Modifier.weight(1f),
                        ) { Text("Meta/Config") }
                    }
                    OutlinedTextField(
                        value = snapshotName,
                        onValueChange = { snapshotName = it },
                        label = { Text("Selection Snapshot Label") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { onSaveSnapshot(snapshotName); snapshotName = "" },
                            modifier = Modifier.weight(1f),
                        ) { Text("Save Local") }
                        OutlinedButton(
                            onClick = { exportLauncher.launch("shieldforge_selection.json") },
                            modifier = Modifier.weight(1f),
                        ) { Text("Export JSON") }
                    }
                    OutlinedButton(
                        onClick = { importLauncher.launch(arrayOf("application/json", "*/*")) },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Import Selection Profile JSON") }
                    if (savedSnapshots.isNotEmpty()) {
                        Text("Saved Snapshots:", style = MaterialTheme.typography.labelMedium, color = ElectricBlue)
                        savedSnapshots.take(3).forEach { snap ->
                            TextButton(onClick = { onLoadSnapshot(snap); showSelectionMenu = false }) {
                                Text("Load '${snap.profileName}' (${snap.selection.totalSelectedCount})")
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showSelectionMenu = false }) { Text("Close") }
            },
        )
    }
}

@Composable
fun DexFilesExplorerTab(
    analysis: ApkAnalysisResult,
    selection: SelectionStateSnapshot,
    onToggleDex: (String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        items(analysis.dexBundle.dexFiles, key = { it.fileName }) { dex ->
            val checked = dex.fileName in selection.selectedDexFiles
            GlassPanelCard(
                onClick = { onToggleDex(dex.fileName) },
                accentColor = if (checked) ElectricBlue else CyberViolet,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = checked, onCheckedChange = { onToggleDex(dex.fileName) })
                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(dex.fileName, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                            StatusPill(text = "v${dex.version}", color = CyberViolet)
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "${dex.classCount} classes • ${dex.methodCount} methods • ${dex.fieldCount} fields • ${dex.packageCount} pkgs • ${formatByteSize(dex.fileSizeBytes.toLong())}",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary,
                        )
                        Spacer(Modifier.height(6.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            CompatibilityBadge(dex.compatibility)
                            ComponentStatusBadge(dex.status)
                        }
                    }
                }
            }
        }
        if (analysis.dexBundle.crossDexReferences.isNotEmpty()) {
            item {
                GlassPanelCard {
                    Text("Cross-DEX Relationships", style = MaterialTheme.typography.titleSmall, color = ElectricBlue)
                    Spacer(Modifier.height(6.dp))
                    analysis.dexBundle.crossDexReferences.take(12).forEach { rel ->
                        MonoCodeText(text = rel)
                    }
                }
            }
        }
    }
}

@Composable
fun PackageExplorerTab(
    analysis: ApkAnalysisResult,
    selection: SelectionStateSnapshot,
    searchQuery: String,
    dexFilter: String?,
    onTogglePackage: (String) -> Unit,
    onSelectAllInPackage: (String) -> Unit,
    onExcludePackage: (String) -> Unit,
    onInspectClass: (DexClassItem) -> Unit,
) {
    val expandedMap = remember { mutableStateOf(setOf<String>()) }
    val filtered = remember(analysis, searchQuery, dexFilter) {
        analysis.dexBundle.packages.filter { pkg ->
            val matchesQuery = searchQuery.isBlank() || pkg.packageName.contains(searchQuery, ignoreCase = true)
            val matchesDex = dexFilter == null || dexFilter in pkg.dexFiles
            matchesQuery && matchesDex
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(filtered, key = { it.packageName }) { pkg ->
            val isSelected = pkg.packageName in selection.selectedPackages
            val isExpanded = pkg.packageName in expandedMap.value
            val childClasses = analysis.dexBundle.classes.filter { it.packageName == pkg.packageName }

            GlassPanelCard(accentColor = if (isSelected) ElectricBlue else com.example.ui.theme.GraphiteBorder) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = isSelected, onCheckedChange = { onTogglePackage(pkg.packageName) })
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .clickable {
                                expandedMap.value = if (isExpanded) {
                                    expandedMap.value - pkg.packageName
                                } else {
                                    expandedMap.value + pkg.packageName
                                }
                            },
                    ) {
                        MonoCodeText(text = pkg.packageName, color = TextPrimary, maxLines = 1)
                        Text(
                            text = "${pkg.classCount} classes • ${pkg.methodCount} methods • ${pkg.dexFiles.joinToString()}",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary,
                        )
                    }
                    IconButton(
                        onClick = {
                            expandedMap.value = if (isExpanded) {
                                expandedMap.value - pkg.packageName
                            } else {
                                expandedMap.value + pkg.packageName
                            }
                        },
                    ) {
                        Icon(
                            if (isExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                            contentDescription = "Expand package",
                            tint = TextSecondary,
                        )
                    }
                }
                if (isExpanded) {
                    Spacer(Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { onSelectAllInPackage(pkg.packageName) }) {
                            Text("Select All Classes")
                        }
                        OutlinedButton(onClick = { onExcludePackage(pkg.packageName) }) {
                            Text("Exclude Pkg")
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    childClasses.take(30).forEach { cls ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onInspectClass(cls) }
                                .padding(vertical = 4.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            MonoCodeText(
                                text = cls.simpleName,
                                color = if (cls.id in selection.selectedClasses) ElectricBlue else TextSecondary,
                                modifier = Modifier.weight(1f),
                            )
                            CompatibilityBadge(cls.compatibility)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ClassExplorerTab(
    analysis: ApkAnalysisResult,
    selection: SelectionStateSnapshot,
    searchQuery: String,
    filterMode: ExplorerFilterMode,
    dexFilter: String?,
    onToggleClass: (String) -> Unit,
    onSaveOverride: (ComponentProtectionOverride) -> Unit,
) {
    var inspectedClass by remember { mutableStateOf<DexClassItem?>(null) }

    val filtered = remember(analysis, searchQuery, filterMode, dexFilter, selection.selectedClasses) {
        analysis.dexBundle.classes.filter { cls ->
            val qMatch = searchQuery.isBlank() || cls.className.contains(searchQuery, ignoreCase = true)
            val dMatch = dexFilter == null || cls.dexFileName == dexFilter
            val fMatch = when (filterMode) {
                ExplorerFilterMode.ALL -> true
                ExplorerFilterMode.SELECTED_ONLY -> cls.id in selection.selectedClasses
                ExplorerFilterMode.TRANSFORMABLE_ONLY -> cls.sourceFile != null
                ExplorerFilterMode.SENSITIVE_ONLY -> cls.hasJniIndicators || cls.hasReflectionIndicators
                ExplorerFilterMode.CAUTION_ONLY -> cls.compatibility != CompatibilityState.COMPATIBLE
            }
            qMatch && dMatch && fMatch
        }.take(250)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(filtered, key = { it.id }) { cls ->
            val checked = cls.id in selection.selectedClasses
            val hasOverride = selection.overrides.containsKey(cls.id)
            GlassPanelCard(
                onClick = { inspectedClass = cls },
                accentColor = if (checked) ElectricBlue else com.example.ui.theme.GraphiteBorder,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = checked, onCheckedChange = { onToggleClass(cls.id) })
                    Column(modifier = Modifier.weight(1f)) {
                        Text(cls.simpleName, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                        MonoCodeText(text = "${cls.packageName} • ${cls.dexFileName}")
                        Spacer(Modifier.height(4.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            CompatibilityBadge(cls.compatibility)
                            ComponentStatusBadge(cls.status)
                            if (hasOverride) {
                                StatusPill(text = "OVERRIDE", color = CyberViolet)
                            }
                        }
                    }
                }
            }
        }
    }

    inspectedClass?.let { cls ->
        ClassOverrideDialog(
            cls = cls,
            existingOverride = selection.overrides[cls.id],
            onDismiss = { inspectedClass = null },
            onSave = {
                onSaveOverride(it)
                inspectedClass = null
            },
        )
    }
}

@Composable
fun MethodExplorerTab(
    analysis: ApkAnalysisResult,
    selection: SelectionStateSnapshot,
    searchQuery: String,
    filterMode: ExplorerFilterMode,
    dexFilter: String?,
    onToggleMethod: (String) -> Unit,
) {
    val filtered = remember(analysis, searchQuery, filterMode, dexFilter, selection.selectedMethods) {
        analysis.dexBundle.methods.filter { m ->
            val q = searchQuery.isBlank() || m.name.contains(searchQuery, true) || m.declaringClass.contains(searchQuery, true)
            val d = dexFilter == null || m.dexFileName == dexFilter
            val f = when (filterMode) {
                ExplorerFilterMode.SELECTED_ONLY -> m.id in selection.selectedMethods
                ExplorerFilterMode.CAUTION_ONLY -> m.compatibility != CompatibilityState.COMPATIBLE
                else -> true
            }
            q && d && f
        }.take(250)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(filtered, key = { it.id }) { m ->
            val checked = m.id in selection.selectedMethods
            GlassPanelCard(onClick = { onToggleMethod(m.id) }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = checked, onCheckedChange = { onToggleMethod(m.id) })
                    Column(modifier = Modifier.weight(1f)) {
                        MonoCodeText(text = m.signature, color = TextPrimary, maxLines = 2)
                        MonoCodeText(text = "${m.declaringClass} (${m.dexFileName})")
                        Spacer(Modifier.height(4.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            StatusPill(text = m.modifiers.joinToString(" ").ifBlank { "pkg" }, color = ElectricBlue)
                            CompatibilityBadge(m.compatibility)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun FieldExplorerTab(
    analysis: ApkAnalysisResult,
    selection: SelectionStateSnapshot,
    searchQuery: String,
    filterMode: ExplorerFilterMode,
    dexFilter: String?,
    onToggleField: (String) -> Unit,
) {
    val filtered = remember(analysis, searchQuery, filterMode, dexFilter, selection.selectedFields) {
        analysis.dexBundle.fields.filter { fld ->
            val q = searchQuery.isBlank() || fld.name.contains(searchQuery, true) || fld.declaringClass.contains(searchQuery, true)
            val d = dexFilter == null || fld.dexFileName == dexFilter
            val f = when (filterMode) {
                ExplorerFilterMode.SELECTED_ONLY -> fld.id in selection.selectedFields
                ExplorerFilterMode.CAUTION_ONLY -> fld.compatibility != CompatibilityState.COMPATIBLE
                else -> true
            }
            q && d && f
        }.take(250)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(filtered, key = { it.id }) { fld ->
            val checked = fld.id in selection.selectedFields
            GlassPanelCard(onClick = { onToggleField(fld.id) }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = checked, onCheckedChange = { onToggleField(fld.id) })
                    Column(modifier = Modifier.weight(1f)) {
                        MonoCodeText(text = "${fld.name}: ${fld.fieldType}", color = TextPrimary)
                        MonoCodeText(text = "${fld.declaringClass} (${fld.dexFileName})")
                        Spacer(Modifier.height(4.dp))
                        CompatibilityBadge(fld.compatibility)
                    }
                }
            }
        }
    }
}

@Composable
fun StringExplorerTab(
    analysis: ApkAnalysisResult,
    selection: SelectionStateSnapshot,
    searchQuery: String,
    filterMode: ExplorerFilterMode,
    dexFilter: String?,
    onToggleString: (String) -> Unit,
) {
    val filtered = remember(analysis, searchQuery, filterMode, dexFilter, selection.selectedStrings) {
        analysis.dexBundle.strings.filter { s ->
            val q = searchQuery.isBlank() || s.value.contains(searchQuery, true)
            val d = dexFilter == null || s.dexFileName == dexFilter
            val f = when (filterMode) {
                ExplorerFilterMode.SELECTED_ONLY -> s.id in selection.selectedStrings
                ExplorerFilterMode.SENSITIVE_ONLY -> s.sensitivity != StringSensitivity.NORMAL
                ExplorerFilterMode.TRANSFORMABLE_ONLY -> s.isSourceFileTag || s.sensitivity != StringSensitivity.NORMAL
                else -> true
            }
            q && d && f
        }.take(300)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(filtered, key = { it.id }) { s ->
            val checked = s.id in selection.selectedStrings
            val badgeColor = when (s.sensitivity) {
                StringSensitivity.POTENTIAL_SECRET_OR_KEY -> CrimsonCritical
                StringSensitivity.URL_OR_ENDPOINT -> AmberCaution
                StringSensitivity.CRYPTO_OR_SQL -> CyberViolet
                StringSensitivity.REFLECTION_OR_JNI -> ElectricBlue
                else -> TextSecondary
            }
            GlassPanelCard(onClick = { onToggleString(s.id) }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = checked, onCheckedChange = { onToggleString(s.id) })
                    Column(modifier = Modifier.weight(1f)) {
                        MonoCodeText(text = s.value, color = TextPrimary, maxLines = 2)
                        Spacer(Modifier.height(4.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            StatusPill(text = s.sensitivity.name, color = badgeColor)
                            StatusPill(text = s.dexFileName, color = ElectricBlue)
                            if (s.isSourceFileTag) {
                                StatusPill(text = "SOURCE TAG", color = EmeraldVerified)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ClassOverrideDialog(
    cls: DexClassItem,
    existingOverride: ComponentProtectionOverride?,
    onDismiss: () -> Unit,
    onSave: (ComponentProtectionOverride) -> Unit,
) {
    var inheritGlobal by remember { mutableStateOf(existingOverride?.inheritGlobal ?: true) }
    var exclude by remember { mutableStateOf(existingOverride?.excludeFromTransformation ?: false) }
    var modules by remember {
        mutableStateOf(
            existingOverride?.enabledModules ?: setOf(
                ProtectionModuleId.STRING_FORGE,
                ProtectionModuleId.DEX_FORGE,
            ),
        )
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(cls.simpleName) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                MonoCodeText(text = cls.className, color = ElectricBlue)
                Text(
                    "DEX: ${cls.dexFileName} • Methods: ${cls.methodCount} • Fields: ${cls.fieldCount} • SourceFile: ${cls.sourceFile ?: "none"}",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Inherit Global Profile", modifier = Modifier.weight(1f))
                    Switch(checked = inheritGlobal, onCheckedChange = { inheritGlobal = it })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Exclude Component", modifier = Modifier.weight(1f))
                    Switch(checked = exclude, onCheckedChange = { exclude = it })
                }
                if (!inheritGlobal && !exclude) {
                    ProtectionModuleId.entries.forEach { mod ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = mod in modules,
                                onCheckedChange = {
                                    modules = if (mod in modules) modules - mod else modules + mod
                                },
                            )
                            Text(mod.displayName, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onSave(
                        ComponentProtectionOverride(
                            componentId = cls.id,
                            componentType = ComponentType.CLASS,
                            displayName = cls.simpleName,
                            inheritGlobal = inheritGlobal,
                            enabledModules = modules,
                            excludeFromTransformation = exclude,
                        ),
                    )
                },
            ) { Text("Save Override") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}
