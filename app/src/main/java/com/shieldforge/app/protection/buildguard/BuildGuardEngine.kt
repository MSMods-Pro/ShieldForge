package com.shieldforge.app.protection.buildguard

import com.shieldforge.app.apk.builder.ApkBuilderEngine
import com.shieldforge.app.apk.signing.ApkSignerEngine
import com.shieldforge.app.core.common.EngineExecutionResult
import com.shieldforge.app.core.common.EngineExecutionState
import com.shieldforge.app.core.common.LogLevel
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.protection.ProtectionPipelineContext

object BuildGuardEngine {
    fun executeOnApk(ctx: ProtectionPipelineContext): EngineExecutionResult {
        val start = System.currentTimeMillis()
        val moduleId = ProtectionModuleId.BUILD_GUARD

        if (moduleId !in ctx.profile.enabledModules) {
            return EngineExecutionResult(
                moduleId = moduleId,
                state = EngineExecutionState.SKIPPED,
                summary = "BuildGuard disabled — output APK will not be rebuilt.",
            )
        }

        ctx.log("BuildGuard", LogLevel.STAGE, "Reconstructing ZIP, aligning STORED entries & applying v1+v2 signatures...")

        val built = ApkBuilderEngine.rebuildAndSignApk(
            inputApk = ctx.inputApk,
            outputApk = ctx.outputApk,
            replacedEntries = ctx.replacedZipEntries,
            addedEntries = ctx.addedZipEntries,
            removedEntries = ctx.removedZipEntries,
            credentials = ctx.credentials,
        )

        val (alignedOk, alignedDetail) = ApkBuilderEngine.verifyZipAlignment(built.outputApk)
        val sigCheck = ApkSignerEngine.inspectApkSignatures(built.outputApk)

        ctx.log(
            "BuildGuard",
            if (sigCheck.verificationPassed) LogLevel.VERIFIED else LogLevel.ERROR,
            "${sigCheck.verificationMessage} • $alignedDetail",
        )

        return EngineExecutionResult(
            moduleId = moduleId,
            state = if (sigCheck.verificationPassed && alignedOk) {
                EngineExecutionState.SUCCEEDED
            } else {
                EngineExecutionState.FAILED
            },
            processedCount = built.totalEntriesWritten,
            artifactsProduced = listOf(
                "Output APK: ${built.outputApk.name} (${built.outputApk.length()} bytes)",
                "Aligned STORED entries: ${built.alignedStoredEntries}",
                "Signing: ${sigCheck.verificationMessage}",
            ),
            summary = "Rebuilt ${built.totalEntriesWritten} entries; ${sigCheck.verificationMessage}.",
            durationMs = System.currentTimeMillis() - start,
        )
    }
}
