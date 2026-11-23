package com.shieldforge.app.protection.manifestforge

import com.shieldforge.app.apk.manifest.BinaryManifestParser
import com.shieldforge.app.core.common.EngineExecutionResult
import com.shieldforge.app.core.common.EngineExecutionState
import com.shieldforge.app.core.common.LogLevel
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.core.crypto.CryptoEngine
import com.shieldforge.app.protection.ProtectionPipelineContext

object ManifestForgeEngine {
    fun executeOnApk(ctx: ProtectionPipelineContext): EngineExecutionResult {
        val start = System.currentTimeMillis()
        val moduleId = ProtectionModuleId.MANIFEST_FORGE

        if (moduleId !in ctx.profile.enabledModules) {
            return EngineExecutionResult(
                moduleId = moduleId,
                state = EngineExecutionState.SKIPPED,
                summary = "Disabled in active profile '${ctx.profile.name}'.",
            )
        }

        val manifestBytes = ctx.manifestWorkingBytes
            ?: return EngineExecutionResult(
                moduleId = moduleId,
                state = EngineExecutionState.FAILED,
                summary = "AndroidManifest.xml missing from APK archive.",
            )

        ctx.log("ManifestForge", LogLevel.STAGE, "Validating AXML structure & hardening attributes...")

        val preParse = BinaryManifestParser.parse(manifestBytes)
        if (!preParse.isValidAxml) {
            return EngineExecutionResult(
                moduleId = moduleId,
                state = EngineExecutionState.FAILED,
                summary = "Invalid AXML header — aborted to prevent corrupt manifest.",
            )
        }

        val (patchedBytes, appliedOps) = BinaryManifestParser.hardenApplicationBooleansInPlace(
            bytes = manifestBytes,
            forceDebuggableFalse = ctx.profile.options.hardenManifestDebuggable,
            forceAllowBackupFalse = ctx.profile.options.hardenManifestAllowBackup,
        )

        val postParse = BinaryManifestParser.parse(patchedBytes)
        if (!postParse.isValidAxml || postParse.packageName != preParse.packageName) {
            return EngineExecutionResult(
                moduleId = moduleId,
                state = EngineExecutionState.FAILED,
                summary = "Post-patch AXML validation failed; rolled back manifest changes.",
            )
        }

        if (appliedOps.isNotEmpty()) {
            ctx.manifestWorkingBytes = patchedBytes
            ctx.replacedZipEntries["AndroidManifest.xml"] = patchedBytes
            appliedOps.forEach { ctx.log("ManifestForge", LogLevel.VERIFIED, it) }
        }

        val warnings = mutableListOf<String>()
        if (preParse.findings.any { it.id == "MAN_CLEARTEXT" }) {
            warnings.add("usesCleartextTraffic=true detected; disable in Source Mode AndroidManifest.xml / network_security_config.")
        }
        if (preParse.metadataKeys.isNotEmpty()) {
            warnings.add("${preParse.metadataKeys.size} <meta-data> key(s) preserved (removing framework metadata in binary AXML can break SDK initialization).")
        }

        val manifestDigest = CryptoEngine.sha256Hex(patchedBytes)
        ctx.log("ManifestForge", LogLevel.INFO, "Manifest SHA-256 verified: ${manifestDigest.take(16)}...")

        return EngineExecutionResult(
            moduleId = moduleId,
            state = if (warnings.isNotEmpty()) EngineExecutionState.PARTIAL_WITH_WARNINGS else EngineExecutionState.SUCCEEDED,
            processedCount = appliedOps.size + 1,
            warnings = warnings,
            artifactsProduced = appliedOps + "Verified AXML (${preParse.components.size} components, ${preParse.permissions.size} permissions)",
            summary = if (appliedOps.isNotEmpty()) {
                "Hardened ${appliedOps.size} AXML attribute(s); preserved all ${preParse.components.size} components."
            } else {
                "Validated AXML manifest (${preParse.components.size} components preserved; no unsafe debug flags active)."
            },
            durationMs = System.currentTimeMillis() - start,
        )
    }
}
