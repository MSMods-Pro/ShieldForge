package com.shieldforge.app.ui.navigation

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavDestination.Companion.hasRoute
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.ui.theme.ElectricBlue
import com.example.ui.theme.GraphiteLow
import com.example.ui.theme.ObsidianSurface
import com.example.ui.theme.ObsidianVoid
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.shieldforge.app.core.common.WorkspaceTab
import com.shieldforge.app.ui.components.StatusPill
import com.shieldforge.app.ui.dashboard.DashboardScreen
import com.shieldforge.app.ui.importscreen.ImportScreen
import com.shieldforge.app.ui.reports.ReportsScreen
import com.shieldforge.app.ui.settings.SettingsScreen
import com.shieldforge.app.ui.signing.SigningManagerScreen
import com.shieldforge.app.ui.state.ShieldForgeViewModel
import com.shieldforge.app.ui.workspace.WorkspaceScreen
import kotlinx.serialization.Serializable

@Serializable object DashboardRoute
@Serializable object ImportRoute
@Serializable object WorkspaceRoute
@Serializable object SigningRoute
@Serializable object ReportsRoute
@Serializable object SettingsRoute

private data class TopLevelNavItem(
    val label: String,
    val route: Any,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val testTag: String,
)

private val topLevelDestinations = listOf(
    TopLevelNavItem("Studio", DashboardRoute, Icons.Filled.Dashboard, Icons.Outlined.Dashboard, "nav_studio"),
    TopLevelNavItem("Import", ImportRoute, Icons.Filled.FolderOpen, Icons.Outlined.FolderOpen, "nav_import"),
    TopLevelNavItem("Forge", WorkspaceRoute, Icons.Filled.Build, Icons.Outlined.Build, "nav_forge"),
    TopLevelNavItem("Signing", SigningRoute, Icons.Filled.Key, Icons.Outlined.Key, "nav_signing"),
    TopLevelNavItem("Reports", ReportsRoute, Icons.Filled.Description, Icons.Outlined.Description, "nav_reports"),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShieldForgeAppRoot(
    viewModel: ShieldForgeViewModel = viewModel(),
) {
    val navController = rememberNavController()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val projects by viewModel.projects.collectAsStateWithLifecycle()
    val buildHistory by viewModel.buildHistory.collectAsStateWithLifecycle()
    val signingProfiles by viewModel.signingProfiles.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentDest = backStackEntry?.destination

    LaunchedEffect(state.statusBanner, state.errorBanner) {
        val msg = state.errorBanner ?: state.statusBanner
        if (msg != null) {
            snackbarHostState.showSnackbar(msg)
            viewModel.dismissBanners()
        }
    }

    fun navigateTopLevel(route: Any) {
        navController.navigate(route) {
            launchSingleTop = true
            restoreState = true
        }
    }

    BoxWithConstraints(modifier = Modifier.fillMaxSize().background(ObsidianVoid)) {
        val isExpanded = maxWidth >= 600.dp

        Scaffold(
            contentWindowInsets = WindowInsets.safeDrawing,
            containerColor = ObsidianVoid,
            snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
            topBar = {
                TopAppBar(
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = ObsidianSurface,
                        titleContentColor = TextPrimary,
                    ),
                    title = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Filled.Shield,
                                contentDescription = "ShieldForge",
                                tint = ElectricBlue,
                                modifier = Modifier.size(22.dp),
                            )
                            Spacer(Modifier.width(8.dp))
                            Column {
                                Text("ShieldForge", style = MaterialTheme.typography.titleLarge, color = TextPrimary)
                                val activePkg = state.currentApkAnalysis?.manifest?.packageName
                                if (activePkg != null) {
                                    Text(activePkg, style = MaterialTheme.typography.labelSmall, color = ElectricBlue)
                                }
                            }
                        }
                    },
                    actions = {
                        state.currentApkAnalysis?.let {
                            StatusPill(
                                text = "${it.dexBundle.dexFiles.size} DEX",
                                color = ElectricBlue,
                                modifier = Modifier.padding(end = 6.dp),
                            )
                        }
                        IconButton(
                            onClick = { navigateTopLevel(SettingsRoute) },
                            modifier = Modifier.testTag("btn_top_settings"),
                        ) {
                            Icon(Icons.Filled.Settings, contentDescription = "Settings", tint = TextSecondary)
                        }
                    },
                )
            },
            bottomBar = {
                if (!isExpanded) {
                    NavigationBar(containerColor = GraphiteLow) {
                        topLevelDestinations.forEach { dest ->
                            val selected = currentDest?.hasRoute(dest.route::class) == true
                            NavigationBarItem(
                                selected = selected,
                                onClick = { navigateTopLevel(dest.route) },
                                icon = {
                                    Icon(
                                        if (selected) dest.selectedIcon else dest.unselectedIcon,
                                        contentDescription = dest.label,
                                    )
                                },
                                label = { Text(dest.label, style = MaterialTheme.typography.labelSmall) },
                                modifier = Modifier.testTag(dest.testTag),
                            )
                        }
                    }
                }
            },
        ) { innerPadding ->
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            ) {
                if (isExpanded) {
                    NavigationRail(
                        containerColor = GraphiteLow,
                        modifier = Modifier.fillMaxHeight(),
                    ) {
                        topLevelDestinations.forEach { dest ->
                            val selected = currentDest?.hasRoute(dest.route::class) == true
                            NavigationRailItem(
                                selected = selected,
                                onClick = { navigateTopLevel(dest.route) },
                                icon = {
                                    Icon(
                                        if (selected) dest.selectedIcon else dest.unselectedIcon,
                                        contentDescription = dest.label,
                                    )
                                },
                                label = { Text(dest.label) },
                                modifier = Modifier.testTag(dest.testTag),
                            )
                        }
                    }
                }

                NavHost(
                    navController = navController,
                    startDestination = DashboardRoute,
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                ) {
                    composable<DashboardRoute> {
                        DashboardScreen(
                            projects = projects,
                            buildHistory = buildHistory,
                            hasActiveProject = state.currentApkAnalysis != null,
                            onProtectApkClick = { navigateTopLevel(ImportRoute) },
                            onImportSourceClick = { navigateTopLevel(ImportRoute) },
                            onAnalyzerClick = {
                                viewModel.setWorkspaceTab(WorkspaceTab.OVERVIEW)
                                navigateTopLevel(WorkspaceRoute)
                            },
                            onInspectOwnApkClick = {
                                viewModel.inspectOwnAppApk {
                                    viewModel.setWorkspaceTab(WorkspaceTab.OVERVIEW)
                                    navigateTopLevel(WorkspaceRoute)
                                }
                            },
                            onDexExplorerClick = {
                                viewModel.setWorkspaceTab(WorkspaceTab.DEX_EXPLORER)
                                navigateTopLevel(WorkspaceRoute)
                            },
                            onEnginesClick = {
                                viewModel.setWorkspaceTab(WorkspaceTab.PROTECTION_CONFIG)
                                navigateTopLevel(WorkspaceRoute)
                            },
                            onSigningClick = { navigateTopLevel(SigningRoute) },
                            onBuildHistoryClick = { navigateTopLevel(ReportsRoute) },
                            onReportsClick = { navigateTopLevel(ReportsRoute) },
                            onSettingsClick = { navigateTopLevel(SettingsRoute) },
                            onOpenRecentProject = { proj ->
                                viewModel.openCachedProject(proj) {
                                    viewModel.setWorkspaceTab(WorkspaceTab.OVERVIEW)
                                    navigateTopLevel(WorkspaceRoute)
                                }
                            },
                        )
                    }

                    composable<ImportRoute> {
                        ImportScreen(
                            isImporting = state.isImporting,
                            isRunningApo = state.isRunningApo,
                            sourceAnalysis = state.currentSourceAnalysis,
                            onImportApkUri = { uri ->
                                viewModel.importApkFromUri(uri) {
                                    viewModel.setWorkspaceTab(WorkspaceTab.OVERVIEW)
                                    navigateTopLevel(WorkspaceRoute)
                                }
                            },
                            onInspectOwnApk = {
                                viewModel.inspectOwnAppApk {
                                    viewModel.setWorkspaceTab(WorkspaceTab.OVERVIEW)
                                    navigateTopLevel(WorkspaceRoute)
                                }
                            },
                            onImportSourceTreeUri = { uri ->
                                viewModel.importSourceProjectTree(uri)
                            },
                            onRunSourceHardening = {
                                viewModel.runSourceProjectHardening()
                            },
                            onOpenWorkspace = { navigateTopLevel(WorkspaceRoute) },
                            onViewReports = { navigateTopLevel(ReportsRoute) },
                        )
                    }

                    composable<WorkspaceRoute> {
                        WorkspaceScreen(
                            state = state,
                            onSelectTab = viewModel::setWorkspaceTab,
                            onImportApkClick = { navigateTopLevel(ImportRoute) },
                            onInspectOwnApkClick = { viewModel.inspectOwnAppApk() },
                            onSearchChange = viewModel::updateSearchQuery,
                            onFilterChange = viewModel::updateFilterMode,
                            onDexFilterChange = viewModel::updateDexFilter,
                            onToggleSelection = viewModel::toggleSelection,
                            onSelectAllInPackage = viewModel::selectAllClassesInPackage,
                            onExcludePackage = viewModel::excludePackage,
                            onBatchSelection = viewModel::batchSelectionAction,
                            onSaveSelectionSnapshot = viewModel::saveSelectionSnapshot,
                            onLoadSelectionSnapshot = viewModel::loadSelectionSnapshot,
                            onExportSelectionJson = viewModel::exportSelectionJsonToUri,
                            onImportSelectionJson = viewModel::importSelectionJsonFromUri,
                            onSaveOverride = viewModel::saveComponentOverride,
                            onSelectProfile = viewModel::selectProfile,
                            onToggleModule = viewModel::toggleModuleInProfile,
                            onUpdateOptions = viewModel::updateProfileOptions,
                            onSetPerDexModules = viewModel::setPerDexModules,
                            onExportProfileJson = viewModel::exportActiveProfileJson,
                            onImportProfileJson = viewModel::importProfileJson,
                            onRunApoPipeline = viewModel::runApoProtectionPipeline,
                            onExportOutputApk = viewModel::exportLatestOutputApk,
                            onExportReportJson = viewModel::exportLatestReportJson,
                            onExportReportTxt = viewModel::exportLatestReportTxt,
                        )
                    }

                    composable<SigningRoute> {
                        SigningManagerScreen(
                            activeProfile = state.activeSigningProfile,
                            savedProfiles = signingProfiles,
                            onCreatePkcs12 = viewModel::createPkcs12SigningKey,
                            onImportPkcs12Uri = viewModel::importPkcs12FromUri,
                            onActivateProfile = viewModel::activateSigningEntity,
                        )
                    }

                    composable<ReportsRoute> {
                        ReportsScreen(
                            latestReport = state.latestReport,
                            buildHistory = buildHistory,
                            onOpenHistoryReport = { item -> viewModel.openBuildReport(item) {} },
                            onExportApkUri = viewModel::exportLatestOutputApk,
                            onExportJsonUri = viewModel::exportLatestReportJson,
                            onExportTxtUri = viewModel::exportLatestReportTxt,
                        )
                    }

                    composable<SettingsRoute> {
                        SettingsScreen(
                            deterministicBuilds = state.deterministicBuildsEnabled,
                            strictAbort = state.strictValidationAbortEnabled,
                            onUpdateSettings = viewModel::updateSettings,
                        )
                    }
                }
            }
        }
    }
}
