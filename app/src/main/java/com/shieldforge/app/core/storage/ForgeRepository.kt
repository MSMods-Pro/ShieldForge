package com.shieldforge.app.core.storage

import android.content.Context
import android.net.Uri
import com.shieldforge.app.apk.parser.ApkAnalysisResult
import com.shieldforge.app.apk.signing.SigningProfile
import com.shieldforge.app.core.common.ProtectionReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File

class ForgeRepository(private val context: Context) {
    private val db = ForgeDatabase.getInstance(context)
    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
    }

    val projects: Flow<List<ProjectEntity>> = db.projectDao().observeAll()
    val buildHistory: Flow<List<BuildHistoryEntity>> = db.buildHistoryDao().observeAll()
    val customProfiles: Flow<List<CustomProfileEntity>> = db.profileDao().observeAll()
    val signingProfiles: Flow<List<SigningProfileEntity>> = db.signingDao().observeAll()

    suspend fun saveApkAnalysis(analysis: ApkAnalysisResult, profileName: String) = withContext(Dispatchers.IO) {
        val cacheDir = File(context.filesDir, "analysis_cache").apply { mkdirs() }
        val cacheFile = File(cacheDir, "${analysis.projectId}.json")
        cacheFile.writeText(json.encodeToString(analysis))

        db.projectDao().upsert(
            ProjectEntity(
                projectId = analysis.projectId,
                name = analysis.manifest.applicationLabel ?: analysis.fileName,
                packageName = analysis.manifest.packageName,
                versionName = "${analysis.manifest.versionName} (${analysis.manifest.versionCode})",
                mode = "PRECOMPILED_APK",
                fileSizeBytes = analysis.fileSizeBytes,
                dexCount = analysis.dexBundle.dexFiles.size,
                classCount = analysis.dexBundle.classes.size,
                lastProfileName = profileName,
                lastStatus = "ANALYZED",
                updatedAtMs = System.currentTimeMillis(),
                analysisCachePath = cacheFile.absolutePath,
            ),
        )
    }

    suspend fun loadCachedApkAnalysis(cachePath: String): ApkAnalysisResult? = withContext(Dispatchers.IO) {
        runCatching {
            val file = File(cachePath)
            if (!file.exists()) return@withContext null
            json.decodeFromString<ApkAnalysisResult>(file.readText())
        }.getOrNull()
    }

    suspend fun recordBuildReport(report: ProtectionReport): File = withContext(Dispatchers.IO) {
        val reportsDir = File(context.filesDir, "reports").apply { mkdirs() }
        val jsonFile = File(reportsDir, "${report.reportId}.json")
        jsonFile.writeText(json.encodeToString(report))

        db.buildHistoryDao().insert(
            BuildHistoryEntity(
                reportId = report.reportId,
                projectId = report.projectId,
                projectName = report.projectName,
                packageName = report.inputPackageName,
                mode = report.mode.name,
                profileName = report.profileName,
                succeeded = report.validationPassed,
                outputPath = report.outputPath,
                reportJsonPath = jsonFile.absolutePath,
                buildDurationMs = report.buildDurationMs,
                createdAtMs = report.generatedAtMs,
                summary = if (report.validationPassed) {
                    "Verified • ${report.selectedModules.size} engines"
                } else {
                    "Validation/Build Issue"
                },
            ),
        )
        jsonFile
    }

    suspend fun loadReport(reportJsonPath: String): ProtectionReport? = withContext(Dispatchers.IO) {
        runCatching {
            val file = File(reportJsonPath)
            if (!file.exists()) return@withContext null
            json.decodeFromString<ProtectionReport>(file.readText())
        }.getOrNull()
    }

    suspend fun saveCustomProfile(id: String, name: String, description: String, profileJson: String) {
        db.profileDao().upsert(
            CustomProfileEntity(
                profileId = id,
                name = name,
                description = description,
                profileJson = profileJson,
                updatedAtMs = System.currentTimeMillis(),
            ),
        )
    }

    suspend fun saveSigningProfile(profile: SigningProfile) {
        db.signingDao().upsert(
            SigningProfileEntity(
                id = profile.id,
                alias = profile.alias,
                storageKind = profile.storageKind,
                keystoreFileName = profile.keystoreFileName,
                commonName = profile.commonName,
                organization = profile.organization,
                sha256Fingerprint = profile.sha256Fingerprint,
                sha1Fingerprint = profile.sha1Fingerprint,
                createdAtMs = profile.createdAtMs,
            ),
        )
    }

    suspend fun exportFileToUri(sourceFile: File, targetUri: Uri) = withContext(Dispatchers.IO) {
        context.contentResolver.openOutputStream(targetUri)?.use { out ->
            sourceFile.inputStream().use { inp -> inp.copyTo(out, bufferSize = 65_536) }
        } ?: throw IllegalStateException("Cannot write to target URI")
    }

    suspend fun exportTextToUri(text: String, targetUri: Uri) = withContext(Dispatchers.IO) {
        context.contentResolver.openOutputStream(targetUri)?.use { out ->
            out.write(text.toByteArray(Charsets.UTF_8))
        } ?: throw IllegalStateException("Cannot write text to target URI")
    }

    suspend fun readTextFromUri(uri: Uri): String = withContext(Dispatchers.IO) {
        context.contentResolver.openInputStream(uri)?.use {
            it.readBytes().toString(Charsets.UTF_8)
        } ?: throw IllegalStateException("Cannot read from selected URI")
    }

    fun formatReadableReport(report: ProtectionReport): String = buildString {
        appendLine("====================================================")
        appendLine("SHIELDFORGE FORGE-X / APO PROTECTION REPORT")
        appendLine("====================================================")
        appendLine("Report ID      : ${report.reportId}")
        appendLine("Project        : ${report.projectName} (${report.inputPackageName})")
        appendLine("Version        : ${report.inputVersionName} (code ${report.inputVersionCode})")
        appendLine("Mode           : ${report.mode.name}")
        appendLine("Profile        : ${report.profileName}")
        appendLine("Duration       : ${report.buildDurationMs} ms")
        appendLine("Input Size     : ${report.inputSizeBytes} bytes")
        appendLine("Output Size    : ${report.outputSizeBytes} bytes")
        appendLine("Output Path    : ${report.outputPath}")
        appendLine("Validation     : ${if (report.validationPassed) "PASSED" else "FAILED"}")
        appendLine("Signing        : ${report.signingSummary}")
        appendLine()
        appendLine("--- ORIGINAL DEX INVENTORY ---")
        report.originalDexInventory.forEach { appendLine(" * $it") }
        appendLine()
        appendLine("--- SELECTED COMPONENTS (${report.selectedComponentCount}) ---")
        appendLine("Active Modules: ${report.selectedModules.joinToString { it.displayName }}")
        appendLine()
        appendLine("--- ENGINE EXECUTION RESULTS ---")
        report.engineResults.forEach { res ->
            appendLine("[${res.moduleId.codeName}] ${res.moduleId.displayName} => ${res.state.name}")
            appendLine("   Summary     : ${res.summary}")
            appendLine("   Processed   : ${res.processedCount}, Skipped: ${res.skippedCount}, Unsupported: ${res.unsupportedCount}")
            res.artifactsProduced.forEach { appendLine("   Artifact    : $it") }
            res.warnings.forEach { appendLine("   Warning     : $it") }
        }
        if (report.dependencyConflicts.isNotEmpty()) {
            appendLine()
            appendLine("--- DEPENDENCY & COMPATIBILITY FINDINGS ---")
            report.dependencyConflicts.forEach { c ->
                appendLine("[${c.severity}] ${c.componentLabel}: ${c.reason} -> ${c.resolution}")
            }
        }
        report.buildFingerprint?.let { fp ->
            appendLine()
            appendLine("--- BUILD FINGERPRINT ---")
            appendLine("Build ID       : ${fp.buildId}")
            appendLine("Input SHA-256  : ${fp.inputSha256}")
            appendLine("Output SHA-256 : ${fp.outputSha256}")
            appendLine("Manifest SHA256: ${fp.manifestSha256}")
            appendLine("ARSC SHA-256   : ${fp.arscSha256}")
            appendLine("Cert SHA-256   : ${fp.signingCertSha256}")
            fp.dexDigests.forEach { (dex, sha) -> appendLine("DEX $dex : $sha") }
        }
        appendLine()
        appendLine("--- VALIDATION CHECKS ---")
        report.validationDetails.forEach { appendLine(" * $it") }
        if (report.notes.isNotEmpty()) {
            appendLine()
            appendLine("--- ARCHITECTURAL NOTES ---")
            report.notes.forEach { appendLine(" * $it") }
        }
    }
}
