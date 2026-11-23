package com.shieldforge.app.protection.dexforge

import com.shieldforge.app.apk.dex.DexBinaryParser
import com.shieldforge.app.core.common.EngineExecutionResult
import com.shieldforge.app.core.common.EngineExecutionState
import com.shieldforge.app.core.common.LogLevel
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.protection.ProtectionPipelineContext

object DexForgeEngine {
    fun executeOnApk(ctx: ProtectionPipelineContext): EngineExecutionResult {
        val start = System.currentTimeMillis()
        val moduleId = ProtectionModuleId.DEX_FORGE

        if (moduleId !in ctx.profile.enabledModules) {
            return EngineExecutionResult(
                moduleId = moduleId,
                state = EngineExecutionState.SKIPPED,
                summary = "Disabled in active profile '${ctx.profile.name}'.",
            )
        }

        ctx.log("DEXForge", LogLevel.STAGE, "Executing per-DEX & per-class structural transformations...")

        val warnings = mutableListOf<String>()
        val artifacts = mutableListOf<String>()
        var strippedClassDefs = 0
        var validatedDexes = 0

        val targetDexNames = if (ctx.selection.selectedDexFiles.isNotEmpty()) {
            ctx.selection.selectedDexFiles
        } else {
            ctx.analysis.dexBundle.dexFiles.map { it.fileName }.toSet()
        }

        for (dexSummary in ctx.analysis.dexBundle.dexFiles) {
            val dexName = dexSummary.fileName
            if (dexName !in targetDexNames) continue
            if (!dexSummary.isSupportedVersion) {
                warnings.add("Skipped $dexName: unsupported DEX version ${dexSummary.version}.")
                continue
            }

            val overrideModules = ctx.profile.perDexOverrides[dexName]
            if (overrideModules != null && moduleId !in overrideModules) {
                ctx.log("DEXForge", LogLevel.INFO, "$dexName skipped by per-DEX profile override")
                continue
            }

            val currentBytes = ctx.dexWorkingBytes[dexName] ?: continue
            if (ctx.profile.options.stripDexSourceFileMetadata) {
                val eligibleIndices = ctx.analysis.dexBundle.classes
                    .filter { cls ->
                        cls.dexFileName == dexName &&
                            cls.sourceFile != null &&
                            !cls.isManifestComponent &&
                            (ctx.selection.selectedClasses.isEmpty() || cls.id in ctx.selection.selectedClasses ||
                                cls.packageName in ctx.selection.selectedPackages)
                    }
                    .map { it.classDefIndex }
                    .toSet()

                if (eligibleIndices.isNotEmpty()) {
                    val (patched, count) = DexBinaryParser.stripSourceFileMetadata(currentBytes, eligibleIndices)
                    if (count > 0) {
                        ctx.dexWorkingBytes[dexName] = patched
                        ctx.replacedZipEntries[dexName] = patched
                        strippedClassDefs += count
                        artifacts.add("$dexName: stripped $count SourceFile debug refs + rebuilt SHA-1/Adler-32")
                    }
                }
            }

            val finalBytes = ctx.dexWorkingBytes[dexName] ?: currentBytes
            val (valid, msg) = DexBinaryParser.validateDexBytes(finalBytes)
            if (valid) {
                validatedDexes++
                ctx.log("DEXForge", LogLevel.VERIFIED, "$dexName: $msg")
            } else {
                return EngineExecutionResult(
                    moduleId = moduleId,
                    state = EngineExecutionState.FAILED,
                    summary = "DEX validation failed for $dexName: $msg",
                    durationMs = System.currentTimeMillis() - start,
                )
            }
        }

        if (ctx.selection.selectedClasses.isNotEmpty() || ctx.selection.selectedMethods.isNotEmpty() || ctx.selection.selectedFields.isNotEmpty()) {
            warnings.add(
                "Precompiled DEX identifier renaming & bytecode CFG flattening are marked SOURCE_R8_REQUIRED to guarantee zero reference/reflection/JNI corruption.",
            )
        }

        return EngineExecutionResult(
            moduleId = moduleId,
            state = if (warnings.isNotEmpty()) EngineExecutionState.PARTIAL_WITH_WARNINGS else EngineExecutionState.SUCCEEDED,
            processedCount = strippedClassDefs + validatedDexes,
            unsupportedCount = ctx.selection.selectedMethods.size + ctx.selection.selectedFields.size,
            warnings = warnings,
            artifactsProduced = artifacts,
            summary = "Validated $validatedDexes DEX file(s); stripped $strippedClassDefs SourceFile metadata refs.",
            durationMs = System.currentTimeMillis() - start,
        )
    }

    fun generateHardenedProguardRules(
        applicationId: String,
        detectedPackages: List<String>,
        manifestEntryPoints: List<String>,
        aggressiveRepackage: Boolean,
    ): String = buildString {
        appendLine("# ========================================================")
        appendLine("# ShieldForge DEXForge + R8 Hardening Rules")
        appendLine("# Target ApplicationId: $applicationId")
        appendLine("# ========================================================")
        appendLine("-optimizationpasses 5")
        appendLine("-allowaccessmodification")
        if (aggressiveRepackage && detectedPackages.isNotEmpty()) {
            val basePkg = detectedPackages.first().substringBeforeLast('.', detectedPackages.first())
            appendLine("-repackageclasses '$basePkg.sf'")
        } else {
            appendLine("-repackageclasses 'o'")
        }
        appendLine("-renamesourcefileattribute SourceFile")
        appendLine("-keepattributes Signature,InnerClasses,EnclosingMethod")
        appendLine("-assumenosideeffects class android.util.Log {")
        appendLine("    public static boolean isLoggable(java.lang.String, int);")
        appendLine("    public static int v(...);")
        appendLine("    public static int d(...);")
        appendLine("}")
        appendLine()
        appendLine("# Preserve Manifest Entry Points")
        manifestEntryPoints.distinct().forEach { entry ->
            appendLine("-keep class $entry { *; }")
        }
        appendLine()
        appendLine("# Preserve JNI native methods")
        appendLine("-keepclasseswithmembernames class * {")
        appendLine("    native <methods>;")
        appendLine("}")
    }
}
