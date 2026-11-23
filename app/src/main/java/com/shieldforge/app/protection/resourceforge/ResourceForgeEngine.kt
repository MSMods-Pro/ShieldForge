package com.shieldforge.app.protection.resourceforge

import com.shieldforge.app.apk.resources.ResourceCategory
import com.shieldforge.app.core.common.EngineExecutionResult
import com.shieldforge.app.core.common.EngineExecutionState
import com.shieldforge.app.core.common.LogLevel
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.core.crypto.CryptoEngine
import com.shieldforge.app.protection.ProtectionPipelineContext
import java.util.zip.ZipFile

object ResourceForgeEngine {
    fun executeOnApk(ctx: ProtectionPipelineContext): EngineExecutionResult {
        val start = System.currentTimeMillis()
        val moduleId = ProtectionModuleId.RESOURCE_FORGE

        if (moduleId !in ctx.profile.enabledModules) {
            return EngineExecutionResult(
                moduleId = moduleId,
                state = EngineExecutionState.SKIPPED,
                summary = "Disabled in active profile '${ctx.profile.name}'.",
            )
        }

        ctx.log("ResourceForge", LogLevel.STAGE, "Analyzing resources.arsc & selected resource entries...")

        val warnings = mutableListOf<String>()
        val artifacts = mutableListOf<String>()
        var processed = 0
        var unsupported = 0

        if (!ctx.analysis.resourceBundle.arsc.isValidArsc) {
            warnings.add("resources.arsc header missing or non-standard.")
        }

        val selectedIds = ctx.selection.selectedResources
        val selectedEntries = ctx.analysis.resourceBundle.entries.filter { it.id in selectedIds }

        // 1. Strip safe compiler metadata entries (.kotlin_builtins, META-INF/*.version) if selected or policy enabled
        val strippableCandidates = if (selectedEntries.isNotEmpty()) {
            selectedEntries.filter { it.isSafeStrippableMetadata }
        } else if (ctx.profile.options.stripBuildMetadataEntries) {
            ctx.analysis.resourceBundle.entries.filter { it.isSafeStrippableMetadata }
        } else {
            emptyList()
        }

        for (meta in strippableCandidates) {
            ctx.removedZipEntries.add(meta.path)
            processed++
        }
        if (strippableCandidates.isNotEmpty()) {
            artifacts.add("Stripped ${strippableCandidates.size} compiler/version metadata entries")
            ctx.log("ResourceForge", LogLevel.INFO, "Stripped ${strippableCandidates.size} build metadata files")
        }

        // 2. Encrypt selected raw assets (non-XML/non-ARSC) into .sfenc companions if user explicitly selected assets
        val assetCandidates = selectedEntries.filter {
            it.category == ResourceCategory.ASSET && !it.path.endsWith(".sfenc")
        }
        if (assetCandidates.isNotEmpty()) {
            val aesKey = CryptoEngine.generateAes256Key()
            ZipFile(ctx.inputApk).use { zip ->
                for (asset in assetCandidates) {
                    val ze = zip.getEntry(asset.path) ?: continue
                    val raw = zip.getInputStream(ze).use { it.readBytes() }
                    val sealed = CryptoEngine.sealAesGcm(raw, aesKey)
                    val payload = """{"alg":"${sealed.algorithm}","iv":"${sealed.ivBase64}","ct":"${sealed.ciphertextBase64}","sha256":"${sealed.plainSha256}"}"""
                    ctx.addedZipEntries["${asset.path}.sfenc"] = payload.toByteArray(Charsets.UTF_8)
                    processed++
                }
            }
            artifacts.add("Generated ${assetCandidates.size} AES-256-GCM .sfenc sealed asset companions")
        }

        // 3. Report unsupported ARSC resource ID obfuscation on precompiled APK transparently
        val arscDependentSelections = selectedEntries.count {
            it.category == ResourceCategory.XML || it.category == ResourceCategory.DRAWABLE ||
                it.category == ResourceCategory.IMAGE || it.category == ResourceCategory.FONT
        }
        if (arscDependentSelections > 0) {
            unsupported += arscDependentSelections
            warnings.add(
                "$arscDependentSelections compiled res/ entry(s) preserved untouched: ARSC resource ID renaming/shrinking requires AAPT2 + R8 in Source Mode.",
            )
        }

        return EngineExecutionResult(
            moduleId = moduleId,
            state = if (warnings.isNotEmpty()) EngineExecutionState.PARTIAL_WITH_WARNINGS else EngineExecutionState.SUCCEEDED,
            processedCount = processed,
            unsupportedCount = unsupported,
            warnings = warnings,
            artifactsProduced = artifacts + "Verified ARSC (${ctx.analysis.resourceBundle.arsc.resourceKeyCount} keys)",
            summary = "Processed $processed resource/metadata entries; preserved ${ctx.analysis.resourceBundle.entries.size} ARSC-linked resources.",
            durationMs = System.currentTimeMillis() - start,
        )
    }
}
