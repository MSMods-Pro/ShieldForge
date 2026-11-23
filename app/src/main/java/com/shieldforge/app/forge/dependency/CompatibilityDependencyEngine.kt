package com.shieldforge.app.forge.dependency

import com.shieldforge.app.apk.parser.ApkAnalysisResult
import com.shieldforge.app.core.common.CompatibilityState
import com.shieldforge.app.core.common.DependencyConflict
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.core.common.SelectionStateSnapshot
import com.shieldforge.app.forge.profiles.ProtectionProfile

data class DependencyPlanSummary(
    val conflicts: List<DependencyConflict>,
    val hasBlockingIssues: Boolean,
    val totalNodesAnalyzed: Int,
    val manifestProtectedClasses: Set<String>,
    val jniProtectedClasses: Set<String>,
    val reflectionProtectedClasses: Set<String>,
)

object CompatibilityDependencyEngine {
    fun analyzeDependencies(
        analysis: ApkAnalysisResult,
        selection: SelectionStateSnapshot,
        profile: ProtectionProfile,
    ): DependencyPlanSummary {
        val conflicts = mutableListOf<DependencyConflict>()
        val manifestClasses = analysis.manifest.components.map { it.name }.toSet()
        val jniClasses = analysis.dexBundle.classes.filter { it.hasJniIndicators }.map { it.className }.toSet()
        val reflectionClasses = analysis.dexBundle.classes.filter { it.hasReflectionIndicators }.map { it.className }.toSet()

        // 1. Check DEX version compatibility
        analysis.dexBundle.dexFiles.forEach { dex ->
            if (!dex.isSupportedVersion && (dex.fileName in selection.selectedDexFiles || selection.selectedDexFiles.isEmpty())) {
                conflicts.add(
                    DependencyConflict(
                        id = "DEP_DEX_${dex.fileName}",
                        componentId = dex.fileName,
                        componentLabel = dex.fileName,
                        reason = "Unsupported DEX version ${dex.version} or invalid checksum.",
                        severity = "BLOCKING",
                        resolution = "Exclude ${dex.fileName} from DEXForge patching; inspect-only mode enforced.",
                    ),
                )
            }
        }

        // 2. Check selected classes for Manifest / JNI / Reflection constraints
        val selectedClassMap = analysis.dexBundle.classes.associateBy { it.id }
        for (clsId in selection.selectedClasses) {
            val cls = selectedClassMap[clsId] ?: continue
            val resolvedModules = profile.resolveModulesForComponent(
                dexFileName = cls.dexFileName,
                componentOverride = selection.overrides[clsId],
            )
            if (cls.isManifestComponent && ProtectionModuleId.DEX_FORGE in resolvedModules) {
                conflicts.add(
                    DependencyConflict(
                        id = "DEP_MAN_${cls.id}",
                        componentId = cls.id,
                        componentLabel = cls.className,
                        reason = "Declared in AndroidManifest.xml (${cls.dexFileName}). Framework requires exact class name.",
                        severity = "WARNING",
                        resolution = "Class name & descriptor preserved; only SourceFile debug metadata may be stripped.",
                    ),
                )
            }
            if (cls.hasJniIndicators && ProtectionModuleId.DEX_FORGE in resolvedModules) {
                conflicts.add(
                    DependencyConflict(
                        id = "DEP_JNI_${cls.id}",
                        componentId = cls.id,
                        componentLabel = cls.className,
                        reason = "Contains native JNI method(s) bound to .so symbols.",
                        severity = "WARNING",
                        resolution = "JNI method signatures preserved automatically by APO.",
                    ),
                )
            }
            if (cls.hasReflectionIndicators && ProtectionModuleId.DEX_FORGE in resolvedModules) {
                conflicts.add(
                    DependencyConflict(
                        id = "DEP_REF_${cls.id}",
                        componentId = cls.id,
                        componentLabel = cls.className,
                        reason = "Reflection pattern detected (Class.forName / getDeclaredMethod).",
                        severity = "WARNING",
                        resolution = "Keep rules generated for R8; precompiled bytecode untouched.",
                    ),
                )
            }
        }

        // 3. Check selected methods/fields in Mode A
        if (selection.selectedMethods.isNotEmpty() || selection.selectedFields.isNotEmpty()) {
            conflicts.add(
                DependencyConflict(
                    id = "DEP_PRECOMPILED_MEMBERS",
                    componentId = "members",
                    componentLabel = "${selection.selectedMethods.size} methods, ${selection.selectedFields.size} fields",
                    reason = "Individual method/field bytecode encryption or symbol renaming cannot be safely applied to precompiled DEX without full IR recompilation.",
                    severity = "WARNING",
                    resolution = "Selected members are validated & included in Mode B R8 keep/obfuscation rules; precompiled APK skips unsafe member rewrites.",
                ),
            )
        }

        // 4. Signing identity notice
        if (ProtectionModuleId.BUILD_GUARD in profile.enabledModules) {
            conflicts.add(
                DependencyConflict(
                    id = "DEP_RESIGN",
                    componentId = "signature",
                    componentLabel = "APK Signing Identity",
                    reason = "Rebuilding an APK invalidates the original signature and requires re-signing.",
                    severity = "WARNING",
                    resolution = "Sign with your authorized keystore in Signing Manager; updates over installs with a different cert require uninstall.",
                ),
            )
        }

        // 5. Native library ABI check
        if (analysis.resourceBundle.nativeLibs.any { !it.isValidElf }) {
            conflicts.add(
                DependencyConflict(
                    id = "DEP_ELF",
                    componentId = "native",
                    componentLabel = "Native .so Libraries",
                    reason = "One or more .so files failed ELF magic validation.",
                    severity = "WARNING",
                    resolution = "BuildGuard will preserve native libraries as 4-byte aligned STORED entries without modifying binary code.",
                ),
            )
        }

        val hasBlocking = conflicts.any { it.severity == "BLOCKING" } &&
            analysis.dexBundle.dexFiles.none { it.isSupportedVersion }

        return DependencyPlanSummary(
            conflicts = conflicts,
            hasBlockingIssues = hasBlocking,
            totalNodesAnalyzed = analysis.dexBundle.classes.size +
                analysis.manifest.components.size +
                analysis.resourceBundle.entries.size,
            manifestProtectedClasses = manifestClasses,
            jniProtectedClasses = jniClasses,
            reflectionProtectedClasses = reflectionClasses,
        )
    }
}
