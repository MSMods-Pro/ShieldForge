package com.shieldforge.app.protection

import com.shieldforge.app.apk.parser.ApkAnalysisResult
import com.shieldforge.app.apk.signing.ResolvedSigningCredentials
import com.shieldforge.app.core.common.LogEntry
import com.shieldforge.app.core.common.LogLevel
import com.shieldforge.app.core.common.SelectionStateSnapshot
import com.shieldforge.app.forge.dependency.DependencyPlanSummary
import com.shieldforge.app.forge.profiles.ProtectionProfile
import java.io.File

class ProtectionPipelineContext(
    val analysis: ApkAnalysisResult,
    val inputApk: File,
    val outputApk: File,
    val selection: SelectionStateSnapshot,
    val profile: ProtectionProfile,
    val dependencyPlan: DependencyPlanSummary,
    val credentials: ResolvedSigningCredentials,
    val onLog: (LogEntry) -> Unit,
) {
    val replacedZipEntries = linkedMapOf<String, ByteArray>()
    val addedZipEntries = linkedMapOf<String, ByteArray>()
    val removedZipEntries = linkedSetOf<String>()
    val dexWorkingBytes = linkedMapOf<String, ByteArray>()
    var manifestWorkingBytes: ByteArray? = null

    fun log(stage: String, level: LogLevel, message: String) {
        onLog(LogEntry(System.currentTimeMillis(), stage, level, message))
    }
}
