package com.shieldforge.app.ui.state

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.shieldforge.app.apk.dex.DexClassItem
import com.shieldforge.app.apk.dex.StringSensitivity
import com.shieldforge.app.apk.importer.ApkImporter
import com.shieldforge.app.apk.importer.SourceProjectAnalysisResult
import com.shieldforge.app.apk.importer.SourceProjectAnalyzer
import com.shieldforge.app.apk.parser.ApkAnalysisResult
import com.shieldforge.app.apk.signing.ApkSignerEngine
import com.shieldforge.app.apk.signing.SigningProfile
import com.shieldforge.app.core.common.ApoStepState
import com.shieldforge.app.core.common.ComponentProtectionOverride
import com.shieldforge.app.core.common.ComponentType
import com.shieldforge.app.core.common.ExplorerFilterMode
import com.shieldforge.app.core.common.LogEntry
import com.shieldforge.app.core.common.LogLevel
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.core.common.ProtectionReport
import com.shieldforge.app.core.common.SelectionProfileExport
import com.shieldforge.app.core.common.SelectionStateSnapshot
import com.shieldforge.app.core.common.WorkspaceTab
import com.shieldforge.app.core.storage.BuildHistoryEntity
import com.shieldforge.app.core.storage.ForgeRepository
import com.shieldforge.app.core.storage.ProjectEntity
import com.shieldforge.app.forge.apo.AdaptiveProtectionOrchestrator
import com.shieldforge.app.forge.dependency.CompatibilityDependencyEngine
import com.shieldforge.app.forge.dependency.DependencyPlanSummary
import com.shieldforge.app.forge.profiles.ProtectionEngineOptions
import com.shieldforge.app.forge.profiles.ProtectionProfile
import com.shieldforge.app.forge.profiles.ProtectionProfilesCatalog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.util.UUID

data class ShieldForgeUiState(
    val isImporting: Boolean = false,
    val isRunningApo: Boolean = false,
    val statusBanner: String? = null,
    val errorBanner: String? = null,
    val currentApkAnalysis: ApkAnalysisResult? = null,
    val currentSourceAnalysis: SourceProjectAnalysisResult? = null,
    val activeWorkspaceTab: WorkspaceTab = WorkspaceTab.OVERVIEW,
    val activeProfile: ProtectionProfile = ProtectionProfilesCatalog.builtInProfiles[1], // Advanced Shield
    val selection: SelectionStateSnapshot = SelectionStateSnapshot(),
    val explorerSearchQuery: String = "",
    val explorerFilter: ExplorerFilterMode = ExplorerFilterMode.ALL,
    val explorerDexFilter: String? = null,
    val dependencyPlan: DependencyPlanSummary? = null,
    val apoSteps: List<ApoStepState> = AdaptiveProtectionOrchestrator.initialSteps(),
    val logs: List<LogEntry> = emptyList(),
    val latestReport: ProtectionReport? = null,
    val activeSigningProfile: SigningProfile? = null,
    val keystorePasswordCache: Map<String, String> = emptyMap(),
    val savedSelectionProfiles: List<SelectionProfileExport> = emptyList(),
    val deterministicBuildsEnabled: Boolean = true,
    val strictValidationAbortEnabled: Boolean = true,
)

class ShieldForgeViewModel(application: Application) : AndroidViewModel(application) {
    private val appContext = application.applicationContext
    val repository = ForgeRepository(appContext)
    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
    }

    private val _uiState = MutableStateFlow(ShieldForgeUiState())
    val uiState: StateFlow<ShieldForgeUiState> = _uiState.asStateFlow()

    val projects: StateFlow<List<ProjectEntity>> = repository.projects.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5_000),
        emptyList(),
    )

    val buildHistory: StateFlow<List<BuildHistoryEntity>> = repository.buildHistory.stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(5_000),
        emptyList(),
    )

    val signingProfiles: StateFlow<List<com.shieldforge.app.core.storage.SigningProfileEntity>> =
        repository.signingProfiles.stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5_000),
            emptyList(),
        )

    init {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                val defaultProfile = ApkSignerEngine.ensureDefaultAndroidKeystoreProfile()
                repository.saveSigningProfile(defaultProfile)
                _uiState.update { it.copy(activeSigningProfile = defaultProfile) }
            }
        }
    }

    fun dismissBanners() {
        _uiState.update { it.copy(statusBanner = null, errorBanner = null) }
    }

    fun setWorkspaceTab(tab: WorkspaceTab) {
        _uiState.update { it.copy(activeWorkspaceTab = tab) }
    }

    fun importApkFromUri(uri: Uri, onReady: () -> Unit = {}) {
        viewModelScope.launch {
            _uiState.update { it.copy(isImporting = true, errorBanner = null, statusBanner = "Analyzing APK binary structure...") }
            runCatching {
                val result = ApkImporter.importFromUri(appContext, uri)
                repository.saveApkAnalysis(result, _uiState.value.activeProfile.name)
                result
            }.onSuccess { result ->
                applyNewApkAnalysis(result)
                onReady()
            }.onFailure { err ->
                _uiState.update {
                    it.copy(
                        isImporting = false,
                        errorBanner = "APK import failed: ${err.message ?: "invalid archive"}",
                    )
                }
            }
        }
    }

    fun inspectOwnAppApk(onReady: () -> Unit = {}) {
        viewModelScope.launch {
            _uiState.update { it.copy(isImporting = true, errorBanner = null, statusBanner = "Inspecting application APK...") }
            runCatching {
                val result = ApkImporter.importOwnApplicationApk(appContext)
                repository.saveApkAnalysis(result, _uiState.value.activeProfile.name)
                result
            }.onSuccess { result ->
                applyNewApkAnalysis(result)
                onReady()
            }.onFailure { err ->
                _uiState.update {
                    it.copy(isImporting = false, errorBanner = "Self-APK audit failed: ${err.message}")
                }
            }
        }
    }

    fun importSourceProjectTree(uri: Uri, onReady: () -> Unit = {}) {
        viewModelScope.launch {
            _uiState.update { it.copy(isImporting = true, errorBanner = null, statusBanner = "Scanning Android source tree...") }
            runCatching {
                SourceProjectAnalyzer.analyzeTreeUri(appContext, uri)
            }.onSuccess { src ->
                _uiState.update {
                    it.copy(
                        isImporting = false,
                        currentSourceAnalysis = src,
                        statusBanner = "Imported source project '${src.projectName}' (${src.kotlinFileCount} kt, ${src.javaFileCount} java)",
                    )
                }
                onReady()
            }.onFailure { err ->
                _uiState.update {
                    it.copy(isImporting = false, errorBanner = "Source project import failed: ${err.message}")
                }
            }
        }
    }

    fun openCachedProject(project: ProjectEntity, onReady: () -> Unit = {}) {
        viewModelScope.launch {
            val cached = repository.loadCachedApkAnalysis(project.analysisCachePath)
            if (cached != null && File(cached.workspaceApkPath).exists()) {
                applyNewApkAnalysis(cached)
                onReady()
            } else {
                _uiState.update { it.copy(errorBanner = "Cached workspace APK for ${project.name} is no longer available.") }
            }
        }
    }

    private fun applyNewApkAnalysis(result: ApkAnalysisResult) {
        val initialSelection = SelectionStateSnapshot(
            selectedDexFiles = result.dexBundle.dexFiles.filter { it.isSupportedVersion }.map { it.fileName }.toSet(),
            selectedStrings = result.dexBundle.strings
                .filter { it.sensitivity != StringSensitivity.NORMAL }
                .take(150)
                .map { it.id }
                .toSet(),
            selectedResources = result.resourceBundle.entries
                .filter { it.isSafeStrippableMetadata || it.isSensitiveConfig }
                .map { it.id }
                .toSet(),
        )
        val depPlan = CompatibilityDependencyEngine.analyzeDependencies(
            analysis = result,
            selection = initialSelection,
            profile = _uiState.value.activeProfile,
        )
        _uiState.update {
            it.copy(
                isImporting = false,
                currentApkAnalysis = result,
                selection = initialSelection,
                dependencyPlan = depPlan,
                activeWorkspaceTab = WorkspaceTab.OVERVIEW,
                statusBanner = "Analyzed ${result.fileName}: ${result.dexBundle.dexFiles.size} DEX, ${result.dexBundle.classes.size} classes",
            )
        }
    }

    fun updateSearchQuery(query: String) {
        _uiState.update { it.copy(explorerSearchQuery = query) }
    }

    fun updateFilterMode(mode: ExplorerFilterMode) {
        _uiState.update { it.copy(explorerFilter = mode) }
    }

    fun updateDexFilter(dexName: String?) {
        _uiState.update { it.copy(explorerDexFilter = dexName) }
    }

    fun toggleSelection(type: ComponentType, id: String) {
        _uiState.update { state ->
            val sel = state.selection
            val updated = when (type) {
                ComponentType.DEX_FILE -> sel.copy(selectedDexFiles = toggleSet(sel.selectedDexFiles, id))
                ComponentType.PACKAGE -> sel.copy(selectedPackages = toggleSet(sel.selectedPackages, id))
                ComponentType.CLASS -> sel.copy(selectedClasses = toggleSet(sel.selectedClasses, id))
                ComponentType.METHOD -> sel.copy(selectedMethods = toggleSet(sel.selectedMethods, id))
                ComponentType.FIELD -> sel.copy(selectedFields = toggleSet(sel.selectedFields, id))
                ComponentType.STRING -> sel.copy(selectedStrings = toggleSet(sel.selectedStrings, id))
                ComponentType.RESOURCE -> sel.copy(selectedResources = toggleSet(sel.selectedResources, id))
                ComponentType.MANIFEST_COMPONENT, ComponentType.MANIFEST_PERMISSION ->
                    sel.copy(selectedManifestItems = toggleSet(sel.selectedManifestItems, id))
                else -> sel
            }
            state.copy(selection = updated).withRecomputedDeps()
        }
    }

    fun selectAllClassesInPackage(packageName: String) {
        val analysis = _uiState.value.currentApkAnalysis ?: return
        val pkgClasses = analysis.dexBundle.classes.filter { it.packageName == packageName }.map { it.id }
        _uiState.update { state ->
            val updated = state.selection.copy(
                selectedPackages = state.selection.selectedPackages + packageName,
                selectedClasses = state.selection.selectedClasses + pkgClasses,
            )
            state.copy(selection = updated).withRecomputedDeps()
        }
    }

    fun excludePackage(packageName: String) {
        val analysis = _uiState.value.currentApkAnalysis ?: return
        val pkgClasses = analysis.dexBundle.classes.filter { it.packageName == packageName }.map { it.id }.toSet()
        _uiState.update { state ->
            val updated = state.selection.copy(
                selectedPackages = state.selection.selectedPackages - packageName,
                selectedClasses = state.selection.selectedClasses - pkgClasses,
            )
            state.copy(selection = updated).withRecomputedDeps()
        }
    }

    fun batchSelectionAction(action: String) {
        val analysis = _uiState.value.currentApkAnalysis ?: return
        _uiState.update { state ->
            val sel = state.selection
            val updated = when (action) {
                "SELECT_ALL_DEX" -> sel.copy(selectedDexFiles = analysis.dexBundle.dexFiles.map { it.fileName }.toSet())
                "SELECT_NONE" -> SelectionStateSnapshot(overrides = sel.overrides)
                "INVERT_CLASSES" -> {
                    val allCls = analysis.dexBundle.classes.map { it.id }.toSet()
                    sel.copy(selectedClasses = allCls - sel.selectedClasses)
                }
                "SELECT_SENSITIVE_STRINGS" -> {
                    val sens = analysis.dexBundle.strings.filter { it.sensitivity != StringSensitivity.NORMAL }.map { it.id }.toSet()
                    sel.copy(selectedStrings = sens)
                }
                "SELECT_ALL_PACKAGES" -> sel.copy(selectedPackages = analysis.dexBundle.packages.map { it.packageName }.toSet())
                "SELECT_SAFE_META_RES" -> {
                    val meta = analysis.resourceBundle.entries.filter { it.isSafeStrippableMetadata || it.isSensitiveConfig }.map { it.id }.toSet()
                    sel.copy(selectedResources = meta)
                }
                else -> sel
            }
            state.copy(selection = updated).withRecomputedDeps()
        }
    }

    fun saveSelectionSnapshot(label: String) {
        val analysis = _uiState.value.currentApkAnalysis ?: return
        val export = SelectionProfileExport(
            profileName = label.ifBlank { "Selection_${System.currentTimeMillis() % 10000}" },
            packageName = analysis.manifest.packageName,
            exportedAtMs = System.currentTimeMillis(),
            selection = _uiState.value.selection,
        )
        _uiState.update {
            it.copy(
                savedSelectionProfiles = listOf(export) + it.savedSelectionProfiles,
                statusBanner = "Saved selection profile '${export.profileName}'",
            )
        }
    }

    fun loadSelectionSnapshot(snapshot: SelectionProfileExport) {
        _uiState.update {
            it.copy(
                selection = snapshot.selection,
                statusBanner = "Loaded selection '${snapshot.profileName}' (${snapshot.selection.totalSelectedCount} items)",
            ).withRecomputedDeps()
        }
    }

    fun exportSelectionJsonToUri(uri: Uri) {
        viewModelScope.launch {
            val analysis = _uiState.value.currentApkAnalysis ?: return@launch
            val export = SelectionProfileExport(
                profileName = "ShieldForge_Selection_${analysis.manifest.packageName}",
                packageName = analysis.manifest.packageName,
                exportedAtMs = System.currentTimeMillis(),
                selection = _uiState.value.selection,
            )
            repository.exportTextToUri(json.encodeToString(export), uri)
            _uiState.update { it.copy(statusBanner = "Exported selection profile JSON") }
        }
    }

    fun importSelectionJsonFromUri(uri: Uri) {
        viewModelScope.launch {
            runCatching {
                val raw = repository.readTextFromUri(uri)
                json.decodeFromString<SelectionProfileExport>(raw)
            }.onSuccess { imported ->
                loadSelectionSnapshot(imported)
            }.onFailure { err ->
                _uiState.update { it.copy(errorBanner = "Invalid selection JSON: ${err.message}") }
            }
        }
    }

    fun saveComponentOverride(override: ComponentProtectionOverride) {
        _uiState.update { state ->
            val map = state.selection.overrides.toMutableMap()
            map[override.componentId] = override
            state.copy(
                selection = state.selection.copy(overrides = map),
                statusBanner = "Updated override for ${override.displayName}",
            ).withRecomputedDeps()
        }
    }

    fun selectProfile(profile: ProtectionProfile) {
        _uiState.update {
            it.copy(activeProfile = profile, statusBanner = "Profile set to ${profile.name}")
                .withRecomputedDeps()
        }
    }

    fun toggleModuleInProfile(moduleId: ProtectionModuleId) {
        _uiState.update { state ->
            val current = state.activeProfile
            val updatedSet = toggleSet(current.enabledModules, moduleId)
            state.copy(
                activeProfile = current.copy(
                    id = "custom_forge",
                    name = if (current.isBuiltIn) "${current.name} (Customized)" else current.name,
                    enabledModules = updatedSet,
                    isBuiltIn = false,
                ),
            ).withRecomputedDeps()
        }
    }

    fun updateProfileOptions(transform: (ProtectionEngineOptions) -> ProtectionEngineOptions) {
        _uiState.update { state ->
            val current = state.activeProfile
            state.copy(
                activeProfile = current.copy(
                    options = transform(current.options),
                    isBuiltIn = false,
                ),
            ).withRecomputedDeps()
        }
    }

    fun setPerDexModules(dexFileName: String, modules: Set<ProtectionModuleId>) {
        _uiState.update { state ->
            val updatedOverrides = state.activeProfile.perDexOverrides.toMutableMap()
            updatedOverrides[dexFileName] = modules
            state.copy(
                activeProfile = state.activeProfile.copy(
                    perDexOverrides = updatedOverrides,
                    isBuiltIn = false,
                ),
                statusBanner = "Updated per-DEX configuration for $dexFileName",
            ).withRecomputedDeps()
        }
    }

    fun exportActiveProfileJson(uri: Uri) {
        viewModelScope.launch {
            val content = ProtectionProfilesCatalog.exportProfileJson(_uiState.value.activeProfile)
            repository.exportTextToUri(content, uri)
            _uiState.update { it.copy(statusBanner = "Exported protection profile JSON") }
        }
    }

    fun importProfileJson(uri: Uri) {
        viewModelScope.launch {
            runCatching {
                val raw = repository.readTextFromUri(uri)
                ProtectionProfilesCatalog.importProfileJson(raw)
            }.onSuccess { prof ->
                selectProfile(prof)
            }.onFailure { err ->
                _uiState.update { it.copy(errorBanner = "Profile import failed: ${err.message}") }
            }
        }
    }

    fun runApoProtectionPipeline() {
        val analysis = _uiState.value.currentApkAnalysis ?: return
        val signingProfile = _uiState.value.activeSigningProfile
        if (signingProfile == null) {
            _uiState.update { it.copy(errorBanner = "Configure a signing key in Signing Manager first.") }
            return
        }

        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isRunningApo = true,
                    activeWorkspaceTab = WorkspaceTab.PROCESSING_LOGS,
                    apoSteps = AdaptiveProtectionOrchestrator.initialSteps(),
                    logs = listOf(LogEntry(stage = "APO", level = LogLevel.INFO, message = "Initializing FORGE-X pipeline...")),
                    errorBanner = null,
                )
            }

            runCatching {
                val pwd = _uiState.value.keystorePasswordCache[signingProfile.id] ?: ""
                val creds = withContext(Dispatchers.IO) {
                    ApkSignerEngine.resolveCredentials(appContext, signingProfile, pwd)
                }
                val report = AdaptiveProtectionOrchestrator.executeApkPipeline(
                    context = appContext,
                    analysis = analysis,
                    selection = _uiState.value.selection,
                    profile = _uiState.value.activeProfile,
                    credentials = creds,
                    onStepUpdate = { steps ->
                        _uiState.update { it.copy(apoSteps = steps) }
                    },
                    onLog = { entry ->
                        _uiState.update { it.copy(logs = (it.logs + entry).takeLast(300)) }
                    },
                )
                repository.recordBuildReport(report)
                report
            }.onSuccess { report ->
                _uiState.update {
                    it.copy(
                        isRunningApo = false,
                        latestReport = report,
                        activeWorkspaceTab = WorkspaceTab.FINAL_REPORT,
                        statusBanner = if (report.validationPassed) {
                            "Protected APK built & verified (${report.buildDurationMs} ms)"
                        } else {
                            "Build completed with validation warnings/errors"
                        },
                    )
                }
            }.onFailure { err ->
                _uiState.update {
                    it.copy(
                        isRunningApo = false,
                        errorBanner = "APO execution error: ${err.message}",
                        logs = it.logs + LogEntry(stage = "APO", level = LogLevel.ERROR, message = err.message ?: "Error"),
                    )
                }
            }
        }
    }

    fun runSourceProjectHardening() {
        val source = _uiState.value.currentSourceAnalysis ?: return
        val certSha = _uiState.value.activeSigningProfile?.sha256Fingerprint
            ?: "0000000000000000000000000000000000000000000000000000000000000000"
        viewModelScope.launch {
            _uiState.update { it.copy(isRunningApo = true, errorBanner = null) }
            runCatching {
                val report = AdaptiveProtectionOrchestrator.executeSourceHardeningPipeline(
                    context = appContext,
                    sourceAnalysis = source,
                    profile = _uiState.value.activeProfile,
                    certSha256 = certSha,
                    onLog = { entry -> _uiState.update { it.copy(logs = it.logs + entry) } },
                )
                repository.recordBuildReport(report)
                report
            }.onSuccess { report ->
                _uiState.update {
                    it.copy(
                        isRunningApo = false,
                        latestReport = report,
                        statusBanner = "Generated Mode B source hardening bundle (${report.engineResults.size} modules)",
                    )
                }
            }.onFailure { err ->
                _uiState.update { it.copy(isRunningApo = false, errorBanner = "Source hardening error: ${err.message}") }
            }
        }
    }

    fun createPkcs12SigningKey(alias: String, password: String, cn: String, org: String) {
        viewModelScope.launch {
            runCatching {
                val profile = withContext(Dispatchers.IO) {
                    ApkSignerEngine.createPkcs12Keystore(appContext, alias, password, cn, org)
                }
                repository.saveSigningProfile(profile)
                profile
            }.onSuccess { profile ->
                _uiState.update {
                    it.copy(
                        activeSigningProfile = profile,
                        keystorePasswordCache = it.keystorePasswordCache + (profile.id to password),
                        statusBanner = "Created PKCS#12 keystore '$alias'",
                    )
                }
            }.onFailure { err ->
                _uiState.update { it.copy(errorBanner = "Key generation failed: ${err.message}") }
            }
        }
    }

    fun importPkcs12FromUri(uri: Uri, password: String) {
        viewModelScope.launch {
            runCatching {
                val bytes = withContext(Dispatchers.IO) {
                    appContext.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw IllegalStateException("Cannot read keystore file")
                }
                val profile = withContext(Dispatchers.IO) {
                    ApkSignerEngine.importPkcs12Keystore(appContext, bytes, password, null)
                }
                repository.saveSigningProfile(profile)
                profile
            }.onSuccess { profile ->
                _uiState.update {
                    it.copy(
                        activeSigningProfile = profile,
                        keystorePasswordCache = it.keystorePasswordCache + (profile.id to password),
                        statusBanner = "Imported keystore alias '${profile.alias}'",
                    )
                }
            }.onFailure { err ->
                _uiState.update { it.copy(errorBanner = "Keystore import failed: ${err.message}") }
            }
        }
    }

    fun activateSigningEntity(entity: com.shieldforge.app.core.storage.SigningProfileEntity, password: String = "") {
        val profile = SigningProfile(
            id = entity.id,
            alias = entity.alias,
            storageKind = entity.storageKind,
            keystoreFileName = entity.keystoreFileName,
            commonName = entity.commonName,
            organization = entity.organization,
            sha256Fingerprint = entity.sha256Fingerprint,
            sha1Fingerprint = entity.sha1Fingerprint,
            createdAtMs = entity.createdAtMs,
        )
        _uiState.update {
            it.copy(
                activeSigningProfile = profile,
                keystorePasswordCache = if (password.isNotEmpty()) it.keystorePasswordCache + (profile.id to password) else it.keystorePasswordCache,
                statusBanner = "Active signer: ${profile.alias}",
            )
        }
    }

    fun openBuildReport(entity: BuildHistoryEntity, onLoaded: () -> Unit) {
        viewModelScope.launch {
            val report = repository.loadReport(entity.reportJsonPath)
            if (report != null) {
                _uiState.update { it.copy(latestReport = report) }
                onLoaded()
            } else {
                _uiState.update { it.copy(errorBanner = "Report file missing on disk.") }
            }
        }
    }

    fun exportLatestOutputApk(uri: Uri) {
        val path = _uiState.value.latestReport?.outputPath ?: return
        val file = File(path)
        if (!file.exists()) {
            _uiState.update { it.copy(errorBanner = "Output APK file not found.") }
            return
        }
        viewModelScope.launch {
            repository.exportFileToUri(file, uri)
            _uiState.update { it.copy(statusBanner = "Exported signed APK successfully") }
        }
    }

    fun exportLatestReportJson(uri: Uri) {
        val report = _uiState.value.latestReport ?: return
        viewModelScope.launch {
            repository.exportTextToUri(json.encodeToString(report), uri)
            _uiState.update { it.copy(statusBanner = "Exported JSON report") }
        }
    }

    fun exportLatestReportTxt(uri: Uri) {
        val report = _uiState.value.latestReport ?: return
        viewModelScope.launch {
            repository.exportTextToUri(repository.formatReadableReport(report), uri)
            _uiState.update { it.copy(statusBanner = "Exported readable security report") }
        }
    }

    fun updateSettings(deterministic: Boolean, strictAbort: Boolean) {
        _uiState.update {
            it.copy(
                deterministicBuildsEnabled = deterministic,
                strictValidationAbortEnabled = strictAbort,
                statusBanner = "Updated FORGE-X workstation preferences",
            )
        }
    }

    private fun ShieldForgeUiState.withRecomputedDeps(): ShieldForgeUiState {
        val apk = currentApkAnalysis ?: return this
        val deps = CompatibilityDependencyEngine.analyzeDependencies(apk, selection, activeProfile)
        return copy(dependencyPlan = deps)
    }

    private fun <T> toggleSet(set: Set<T>, item: T): Set<T> =
        if (item in set) set - item else set + item

    fun findClassById(classId: String): DexClassItem? =
        _uiState.value.currentApkAnalysis?.dexBundle?.classes?.firstOrNull { it.id == classId }
}
