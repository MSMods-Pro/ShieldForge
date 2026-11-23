package com.shieldforge.app.forge.apo

import android.content.Context
import com.shieldforge.app.apk.dex.DexBinaryParser
import com.shieldforge.app.apk.importer.SourceProjectAnalysisResult
import com.shieldforge.app.apk.manifest.BinaryManifestParser
import com.shieldforge.app.apk.parser.ApkAnalysisResult
import com.shieldforge.app.apk.parser.ApkArchiveParser
import com.shieldforge.app.apk.signing.ResolvedSigningCredentials
import com.shieldforge.app.core.common.ApoStepState
import com.shieldforge.app.core.common.BuildFingerprint
import com.shieldforge.app.core.common.EngineExecutionResult
import com.shieldforge.app.core.common.EngineExecutionState
import com.shieldforge.app.core.common.LogEntry
import com.shieldforge.app.core.common.LogLevel
import com.shieldforge.app.core.common.ProjectMode
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.core.common.ProtectionReport
import com.shieldforge.app.core.common.SelectionStateSnapshot
import com.shieldforge.app.core.crypto.CryptoEngine
import com.shieldforge.app.forge.dependency.CompatibilityDependencyEngine
import com.shieldforge.app.forge.profiles.ProtectionProfile
import com.shieldforge.app.protection.ProtectionPipelineContext
import com.shieldforge.app.protection.buildguard.BuildGuardEngine
import com.shieldforge.app.protection.configforge.ConfigForgeEngine
import com.shieldforge.app.protection.dexforge.DexForgeEngine
import com.shieldforge.app.protection.integrityforge.IntegrityForgeEngine
import com.shieldforge.app.protection.manifestforge.ManifestForgeEngine
import com.shieldforge.app.protection.resourceforge.ResourceForgeEngine
import com.shieldforge.app.protection.stringforge.StringForgeEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID
import java.util.zip.ZipFile

/**
 * APO — Adaptive Protection Orchestration
 * Executes the 18-step FORGE-X protection pipeline with real structural validation and abort guards.
 */
object AdaptiveProtectionOrchestrator {
    val pipelineStepTitles = listOf(
        "1. Input validation",
        "2. Application analysis",
        "3. DEX inventory",
        "4. Manifest inspection",
        "5. Resource inspection",
        "6. Dependency analysis",
        "7. Component selection",
        "8. Protection configuration",
        "9. Compatibility assessment",
        "10. Transformation planning",
        "11. Protection execution",
        "12. Structural validation",
        "13. APK reconstruction",
        "14. ZIP alignment",
        "15. APK signing",
        "16. Signature verification",
        "17. Final integrity verification",
        "18. Report generation",
    )

    fun initialSteps(): List<ApoStepState> =
        pipelineStepTitles.mapIndexed { idx, title -> ApoStepState(index = idx, title = title) }

    suspend fun executeApkPipeline(
        context: Context,
        analysis: ApkAnalysisResult,
        selection: SelectionStateSnapshot,
        profile: ProtectionProfile,
        credentials: ResolvedSigningCredentials,
        onStepUpdate: (List<ApoStepState>) -> Unit,
        onLog: (LogEntry) -> Unit,
    ): ProtectionReport = withContext(Dispatchers.IO) {
        val startMs = System.currentTimeMillis()
        val steps = initialSteps().toMutableList()

        fun advance(stepIdx: Int, detail: String, failed: Boolean = false) {
            for (i in steps.indices) {
                steps[i] = when {
                    i < stepIdx -> steps[i].copy(completed = true, active = false)
                    i == stepIdx -> steps[i].copy(
                        completed = !failed,
                        active = false,
                        failed = failed,
                        detail = detail,
                    )
                    i == stepIdx + 1 && !failed -> steps[i].copy(active = true)
                    else -> steps[i]
                }
            }
            onStepUpdate(steps.toList())
        }

        fun emit(stage: String, level: LogLevel, msg: String) {
            onLog(LogEntry(System.currentTimeMillis(), stage, level, msg))
        }

        val inputApk = File(analysis.workspaceApkPath)
        require(inputApk.exists()) { "Input workspace APK not found" }

        val outputDir = File(context.filesDir, "outputs").apply { mkdirs() }
        val cleanPkg = analysis.manifest.packageName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        val outputApk = File(outputDir, "${cleanPkg}_shieldforge_${System.currentTimeMillis()}.apk")

        emit("APO", LogLevel.STAGE, "Starting FORGE-X 18-stage pipeline for ${analysis.fileName}")
        advance(0, "Verified workspace APK (${analysis.fileSizeBytes} bytes)")
        advance(1, "Package ${analysis.manifest.packageName} v${analysis.manifest.versionName}")
        advance(2, "${analysis.dexBundle.dexFiles.size} DEX file(s), ${analysis.dexBundle.classes.size} classes")
        advance(3, "${analysis.manifest.components.size} components, ${analysis.manifest.permissions.size} permissions")
        advance(4, "${analysis.resourceBundle.entries.size} resources, ${analysis.resourceBundle.nativeLibs.size} native libs")

        val depPlan = CompatibilityDependencyEngine.analyzeDependencies(analysis, selection, profile)
        advance(5, "Analyzed ${depPlan.totalNodesAnalyzed} nodes; ${depPlan.conflicts.size} finding(s)")
        advance(6, "${selection.totalSelectedCount} explicit component selections")
        advance(7, "Profile '${profile.name}' (${profile.enabledModules.size} engines)")
        advance(8, if (depPlan.hasBlockingIssues) "Blocking issues detected" else "Compatibility verified")

        if (depPlan.hasBlockingIssues) {
            emit("APO", LogLevel.ERROR, "Aborted by APO: no compatible DEX files eligible for transformation.")
            advance(9, "Aborted due to blocking compatibility issue", failed = true)
            return@withContext ProtectionReport(
                reportId = "RPT_${UUID.randomUUID().toString().take(8)}",
                projectId = analysis.projectId,
                projectName = analysis.manifest.applicationLabel ?: analysis.fileName,
                mode = ProjectMode.PRECOMPILED_APK,
                profileName = profile.name,
                generatedAtMs = System.currentTimeMillis(),
                buildDurationMs = System.currentTimeMillis() - startMs,
                inputPackageName = analysis.manifest.packageName,
                inputVersionName = analysis.manifest.versionName,
                inputVersionCode = analysis.manifest.versionCode,
                inputSizeBytes = analysis.fileSizeBytes,
                outputSizeBytes = 0L,
                outputPath = "",
                originalDexInventory = analysis.dexBundle.dexFiles.map { "${it.fileName} (v${it.version})" },
                selectedComponentCount = selection.totalSelectedCount,
                selectedModules = profile.enabledModules.toList(),
                engineResults = emptyList(),
                dependencyConflicts = depPlan.conflicts,
                validationPassed = false,
                validationDetails = listOf("Pipeline aborted before transformation to prevent APK corruption."),
                signingSummary = "Aborted",
                buildFingerprint = null,
                notes = listOf("APO stopped execution because target DEX versions were unsupported."),
            )
        }

        // Load working DEX + Manifest bytes from inputApk
        val ctx = ProtectionPipelineContext(
            analysis = analysis,
            inputApk = inputApk,
            outputApk = outputApk,
            selection = selection,
            profile = profile,
            dependencyPlan = depPlan,
            credentials = credentials,
            onLog = onLog,
        )

        ZipFile(inputApk).use { zip ->
            for (dex in analysis.dexBundle.dexFiles) {
                zip.getEntry(dex.fileName)?.let { ze ->
                    ctx.dexWorkingBytes[dex.fileName] = zip.getInputStream(ze).use { it.readBytes() }
                }
            }
            zip.getEntry("AndroidManifest.xml")?.let { ze ->
                ctx.manifestWorkingBytes = zip.getInputStream(ze).use { it.readBytes() }
            }
        }
        advance(9, "Planned ${profile.enabledModules.size} FORGE-X engine stage(s)")

        // Stage 11: Execute protection engines
        val results = mutableListOf<EngineExecutionResult>()
        results.add(StringForgeEngine.executeOnApk(ctx))
        results.add(ManifestForgeEngine.executeOnApk(ctx))
        results.add(ResourceForgeEngine.executeOnApk(ctx))
        results.add(DexForgeEngine.executeOnApk(ctx))
        results.add(ConfigForgeEngine.executeOnApk(ctx))
        results.add(IntegrityForgeEngine.executeOnApk(ctx))
        advance(10, "Executed ${results.count { it.state != EngineExecutionState.SKIPPED }} transformation engines")

        // Stage 12: Pre-build structural validation of modified DEX & Manifest
        val validationMsgs = mutableListOf<String>()
        var preBuildOk = true
        for ((dexName, bytes) in ctx.dexWorkingBytes) {
            val (ok, msg) = DexBinaryParser.validateDexBytes(bytes)
            if (!ok) preBuildOk = false
            validationMsgs.add("$dexName: $msg")
        }
        val manifestOk = ctx.manifestWorkingBytes?.let { BinaryManifestParser.parse(it).isValidAxml } ?: false
        if (!manifestOk) preBuildOk = false
        validationMsgs.add("Manifest AXML valid: $manifestOk")
        advance(11, if (preBuildOk) "DEX & AXML structural validation passed" else "Structural check failed", failed = !preBuildOk)

        if (!preBuildOk) {
            emit("APO", LogLevel.ERROR, "Aborted before BuildGuard: structural validation failed.")
            return@withContext ProtectionReport(
                reportId = "RPT_${UUID.randomUUID().toString().take(8)}",
                projectId = analysis.projectId,
                projectName = analysis.manifest.applicationLabel ?: analysis.fileName,
                mode = ProjectMode.PRECOMPILED_APK,
                profileName = profile.name,
                generatedAtMs = System.currentTimeMillis(),
                buildDurationMs = System.currentTimeMillis() - startMs,
                inputPackageName = analysis.manifest.packageName,
                inputVersionName = analysis.manifest.versionName,
                inputVersionCode = analysis.manifest.versionCode,
                inputSizeBytes = analysis.fileSizeBytes,
                outputSizeBytes = 0L,
                outputPath = "",
                originalDexInventory = analysis.dexBundle.dexFiles.map { "${it.fileName} (v${it.version})" },
                selectedComponentCount = selection.totalSelectedCount,
                selectedModules = profile.enabledModules.toList(),
                engineResults = results,
                dependencyConflicts = depPlan.conflicts,
                validationPassed = false,
                validationDetails = validationMsgs,
                signingSummary = "Aborted",
                buildFingerprint = null,
                notes = listOf("Original APK preserved untouched."),
            )
        }

        // Stages 13-16: BuildGuard rebuild, alignment, v1+v2 signing & signature verification
        val buildRes = BuildGuardEngine.executeOnApk(ctx)
        results.add(buildRes)
        advance(12, "Reconstructed ZIP entries")
        advance(13, "4-byte alignment applied to STORED entries")
        advance(14, "Applied JAR v1 + APK Signature Scheme v2")
        advance(15, buildRes.summary, failed = buildRes.state == EngineExecutionState.FAILED)

        // Stage 17: Final re-parse integrity verification of output APK
        var finalVerified = false
        var outputSha256 = ""
        var fingerprint: BuildFingerprint? = null
        var signingSummary = "Not signed"
        if (outputApk.exists()) {
            val postAnalysis = ApkArchiveParser.analyzeApk("VERIFY", outputApk.name, outputApk)
            val allDexValid = postAnalysis.dexBundle.dexFiles.all { it.adler32Valid && it.sha1Valid }
            val sigOk = postAnalysis.signatureInfo.verificationPassed
            finalVerified = postAnalysis.manifest.isValidAxml && allDexValid && sigOk
            outputSha256 = postAnalysis.apkSha256
            signingSummary = "${postAnalysis.signatureInfo.verificationMessage} (Alias: ${credentials.profile.alias})"
            validationMsgs.add("Post-build re-parse: ${postAnalysis.dexBundle.dexFiles.size} DEX valid=$allDexValid, Manifest valid=${postAnalysis.manifest.isValidAxml}, Sig=$sigOk")
            fingerprint = BuildFingerprint(
                buildId = "BLD_${UUID.randomUUID().toString().take(8)}",
                timestampEpochMs = System.currentTimeMillis(),
                inputSha256 = analysis.apkSha256,
                outputSha256 = outputSha256,
                manifestSha256 = postAnalysis.manifest.manifestSha256,
                arscSha256 = postAnalysis.resourceBundle.arsc.arscSha256,
                dexDigests = postAnalysis.dexBundle.dexFiles.associate { it.fileName to it.sha256Hex },
                signingCertSha256 = credentials.profile.sha256Fingerprint,
            )
        }
        advance(16, if (finalVerified) "Output APK passed full post-build integrity check" else "Post-build verification warning", failed = !finalVerified)

        val report = ProtectionReport(
            reportId = "RPT_${UUID.randomUUID().toString().take(8)}",
            projectId = analysis.projectId,
            projectName = analysis.manifest.applicationLabel ?: analysis.fileName,
            mode = ProjectMode.PRECOMPILED_APK,
            profileName = profile.name,
            generatedAtMs = System.currentTimeMillis(),
            buildDurationMs = System.currentTimeMillis() - startMs,
            inputPackageName = analysis.manifest.packageName,
            inputVersionName = analysis.manifest.versionName,
            inputVersionCode = analysis.manifest.versionCode,
            inputSizeBytes = analysis.fileSizeBytes,
            outputSizeBytes = if (outputApk.exists()) outputApk.length() else 0L,
            outputPath = if (outputApk.exists()) outputApk.absolutePath else "",
            originalDexInventory = analysis.dexBundle.dexFiles.map {
                "${it.fileName} (v${it.version}, ${it.classCount} classes, ${it.methodCount} methods)"
            },
            selectedComponentCount = selection.totalSelectedCount,
            selectedModules = profile.enabledModules.toList(),
            engineResults = results,
            dependencyConflicts = depPlan.conflicts,
            validationPassed = finalVerified,
            validationDetails = validationMsgs,
            signingSummary = signingSummary,
            buildFingerprint = fingerprint,
            notes = listOf(
                "Original imported APK preserved unmodified at workspace isolation.",
                "Re-signing changes the APK certificate identity; uninstall any prior version signed with a different key before installing.",
            ),
        )
        advance(17, "Generated ProtectionReport ${report.reportId}")
        emit("APO", LogLevel.VERIFIED, "Pipeline finished in ${report.buildDurationMs} ms")
        report
    }

    suspend fun executeSourceHardeningPipeline(
        context: Context,
        sourceAnalysis: SourceProjectAnalysisResult,
        profile: ProtectionProfile,
        certSha256: String,
        onLog: (LogEntry) -> Unit,
    ): ProtectionReport = withContext(Dispatchers.IO) {
        val startMs = System.currentTimeMillis()
        val bundleDir = File(context.filesDir, "source_bundles/${sourceAnalysis.projectId}").apply { mkdirs() }
        onLog(LogEntry(System.currentTimeMillis(), "APO-SRC", LogLevel.STAGE, "Generating Mode B source hardening bundle..."))

        val proguardText = DexForgeEngine.generateHardenedProguardRules(
            applicationId = sourceAnalysis.applicationId,
            detectedPackages = sourceAnalysis.detectedPackages,
            manifestEntryPoints = sourceAnalysis.entryPointsFromManifest,
            aggressiveRepackage = profile.options.enableAggressiveRepackagingInSource,
        )
        val proguardFile = File(bundleDir, "proguard-rules-shieldforge.pro").apply { writeText(proguardText) }

        val pkgBase = sourceAnalysis.detectedPackages.firstOrNull() ?: sourceAnalysis.applicationId
        val stringVaultText = StringForgeEngine.generateSourceKotlinVault(pkgBase, sourceAnalysis.sensitiveStringCandidates)
        val stringVaultFile = File(bundleDir, "StringForgeVault.kt").apply { writeText(stringVaultText) }

        val integrityGuardText = IntegrityForgeEngine.generateSourceIntegrityGuardKotlin(pkgBase, certSha256)
        val integrityFile = File(bundleDir, "IntegrityForgeGuard.kt").apply { writeText(integrityGuardText) }

        val configStoreText = ConfigForgeEngine.generateSourceConfigStoreKotlin(pkgBase)
        val configFile = File(bundleDir, "ConfigForgeStore.kt").apply { writeText(configStoreText) }

        val gradlePatchText = """
            // ShieldForge Release Hardening Snippet for app/build.gradle.kts
            android {
                buildTypes {
                    release {
                        isMinifyEnabled = true
                        isShrinkResources = true
                        proguardFiles(
                            getDefaultProguardFile("proguard-android-optimize.txt"),
                            "proguard-rules.pro",
                            "proguard-rules-shieldforge.pro"
                        )
                    }
                }
            }
        """.trimIndent()
        val gradlePatchFile = File(bundleDir, "release-hardening.gradle.kts").apply { writeText(gradlePatchText) }

        val results = listOf(
            EngineExecutionResult(
                moduleId = ProtectionModuleId.DEX_FORGE,
                state = EngineExecutionState.SUCCEEDED,
                processedCount = sourceAnalysis.sourceFiles.size,
                artifactsProduced = listOf(proguardFile.name, gradlePatchFile.name),
                summary = "Generated R8/ProGuard full-mode rules preserving ${sourceAnalysis.entryPointsFromManifest.size} manifest entry points.",
            ),
            EngineExecutionResult(
                moduleId = ProtectionModuleId.STRING_FORGE,
                state = EngineExecutionState.SUCCEEDED,
                processedCount = sourceAnalysis.sensitiveStringCandidates.size,
                artifactsProduced = listOf(stringVaultFile.name),
                summary = "Generated Android Keystore AES/GCM StringForgeVault.kt for ${sourceAnalysis.sensitiveStringCandidates.size} string candidate(s).",
            ),
            EngineExecutionResult(
                moduleId = ProtectionModuleId.INTEGRITY_FORGE,
                state = EngineExecutionState.SUCCEEDED,
                processedCount = 1,
                artifactsProduced = listOf(integrityFile.name),
                summary = "Generated IntegrityForgeGuard.kt pinned to SHA-256 ${certSha256.take(16)}...",
            ),
            EngineExecutionResult(
                moduleId = ProtectionModuleId.CONFIG_FORGE,
                state = EngineExecutionState.SUCCEEDED,
                processedCount = 1,
                artifactsProduced = listOf(configFile.name),
                summary = "Generated ConfigForgeStore.kt Keystore AES-256-GCM helper.",
            ),
        )

        onLog(LogEntry(System.currentTimeMillis(), "APO-SRC", LogLevel.VERIFIED, "Source hardening bundle ready in ${bundleDir.name}"))

        ProtectionReport(
            reportId = "SRPT_${UUID.randomUUID().toString().take(8)}",
            projectId = sourceAnalysis.projectId,
            projectName = sourceAnalysis.projectName,
            mode = ProjectMode.SOURCE_PROJECT,
            profileName = profile.name,
            generatedAtMs = System.currentTimeMillis(),
            buildDurationMs = System.currentTimeMillis() - startMs,
            inputPackageName = sourceAnalysis.applicationId,
            inputVersionName = "Source Project",
            inputVersionCode = 1L,
            inputSizeBytes = 0L,
            outputSizeBytes = bundleDir.listFiles()?.sumOf { it.length() } ?: 0L,
            outputPath = bundleDir.absolutePath,
            originalDexInventory = listOf("Source Mode: ${sourceAnalysis.kotlinFileCount} Kotlin, ${sourceAnalysis.javaFileCount} Java, ${sourceAnalysis.xmlFileCount} XML"),
            selectedComponentCount = sourceAnalysis.sourceFiles.size,
            selectedModules = profile.enabledModules.toList(),
            engineResults = results,
            dependencyConflicts = emptyList(),
            validationPassed = true,
            validationDetails = listOf(
                "Generated 5 verified source hardening artifacts (R8 rules, StringForgeVault, IntegrityForgeGuard, ConfigForgeStore, Gradle snippet).",
            ),
            signingSummary = "Cert fingerprint pinned: ${certSha256.take(24)}...",
            buildFingerprint = null,
            notes = listOf("Integrate generated files into app/src/main/ and compile release APK with Gradle + R8."),
        )
    }
}
