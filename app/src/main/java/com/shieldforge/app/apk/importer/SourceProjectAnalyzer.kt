package com.shieldforge.app.apk.importer

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class SourceFileItem(
    val relativePath: String,
    val language: String, // "Kotlin", "Java", "Gradle", "XML", "ProGuard"
    val lineCount: Int,
    val packageName: String,
    val hardcodedStringLiterals: List<String>,
    val reflectionOrJniHits: List<String>,
)

@Serializable
data class SourceProjectAnalysisResult(
    val projectId: String,
    val projectName: String,
    val treeUriString: String,
    val applicationId: String,
    val hasGradleWrapperOrBuild: Boolean,
    val hasR8MinifyEnabled: Boolean,
    val hasResourceShrinking: Boolean,
    val hasProguardRulesFile: Boolean,
    val kotlinFileCount: Int,
    val javaFileCount: Int,
    val xmlFileCount: Int,
    val detectedPackages: List<String>,
    val sourceFiles: List<SourceFileItem>,
    val sensitiveStringCandidates: List<String>,
    val entryPointsFromManifest: List<String>,
    val analyzedAtMs: Long,
)

object SourceProjectAnalyzer {
    private val STRING_LITERAL_REGEX = Regex("\"([^\"\\\\]{4,120})\"")
    private val PACKAGE_REGEX = Regex("^\\s*package\\s+([a-zA-Z0-9_.]+)", RegexOption.MULTILINE)
    private val APP_ID_REGEX = Regex("applicationId\\s*[= ]\\s*[\"']([^\"']+)[\"']")
    private val COMPONENT_NAME_REGEX = Regex("android:name\\s*=\\s*[\"']([^\"']+)[\"']")

    suspend fun analyzeTreeUri(
        context: Context,
        treeUri: Uri,
    ): SourceProjectAnalysisResult = withContext(Dispatchers.IO) {
        val root = DocumentFile.fromTreeUri(context, treeUri)
            ?: throw IllegalArgumentException("Unable to access selected directory")

        val projectId = "SRC_${UUID.randomUUID().toString().take(8)}"
        val projectName = root.name ?: "AndroidSourceProject"

        var hasGradle = false
        var hasMinify = false
        var hasShrinkRes = false
        var hasProguard = false
        var appId = "com.example.app"
        var ktCount = 0
        var javaCount = 0
        var xmlCount = 0

        val sourceFiles = mutableListOf<SourceFileItem>()
        val packages = linkedSetOf<String>()
        val sensitiveStrings = linkedSetOf<String>()
        val manifestComponents = linkedSetOf<String>()

        fun walk(dir: DocumentFile, prefix: String, depth: Int) {
            if (depth > 8 || sourceFiles.size >= 400) return
            val children = dir.listFiles()
            for (child in children) {
                val name = child.name ?: continue
                if (name == ".git" || name == ".gradle" || name == "build" || name == ".idea") continue
                val relPath = if (prefix.isEmpty()) name else "$prefix/$name"
                if (child.isDirectory) {
                    walk(child, relPath, depth + 1)
                } else if (child.isFile) {
                    val lower = name.lowercase()
                    when {
                        lower == "build.gradle" || lower == "build.gradle.kts" || lower == "settings.gradle" || lower == "settings.gradle.kts" -> {
                            hasGradle = true
                            val text = readTextSafely(context, child.uri, 256_000)
                            APP_ID_REGEX.find(text)?.groupValues?.getOrNull(1)?.let { appId = it }
                            if (text.contains("isMinifyEnabled = true") || text.contains("minifyEnabled true")) {
                                hasMinify = true
                            }
                            if (text.contains("isShrinkResources = true") || text.contains("shrinkResources true")) {
                                hasShrinkRes = true
                            }
                        }
                        lower == "proguard-rules.pro" || lower == "proguard-android.txt" -> {
                            hasProguard = true
                        }
                        lower == "androidmanifest.xml" -> {
                            xmlCount++
                            val text = readTextSafely(context, child.uri, 256_000)
                            COMPONENT_NAME_REGEX.findAll(text).forEach { match ->
                                val comp = match.groupValues[1]
                                if (comp.contains(".")) manifestComponents.add(comp)
                            }
                        }
                        lower.endsWith(".kt") || lower.endsWith(".java") -> {
                            val isKt = lower.endsWith(".kt")
                            if (isKt) ktCount++ else javaCount++
                            val text = readTextSafely(context, child.uri, 256_000)
                            val pkg = PACKAGE_REGEX.find(text)?.groupValues?.getOrNull(1) ?: ""
                            if (pkg.isNotBlank()) packages.add(pkg)
                            val literals = STRING_LITERAL_REGEX.findAll(text)
                                .map { it.groupValues[1] }
                                .filter { lit ->
                                    lit.startsWith("http") || lit.contains("secret", true) ||
                                        lit.contains("token", true) || lit.contains("key", true) ||
                                        lit.contains("AES", false) || lit.length >= 12
                                }
                                .distinct()
                                .take(25)
                                .toList()
                            sensitiveStrings.addAll(literals)

                            val refHits = buildList {
                                if (text.contains("Class.forName")) add("Class.forName")
                                if (text.contains("getDeclaredMethod")) add("getDeclaredMethod")
                                if (text.contains("System.loadLibrary")) add("System.loadLibrary")
                                if (text.contains("external fun ")) add("JNI external fun")
                            }

                            sourceFiles.add(
                                SourceFileItem(
                                    relativePath = relPath,
                                    language = if (isKt) "Kotlin" else "Java",
                                    lineCount = text.lines().size,
                                    packageName = pkg,
                                    hardcodedStringLiterals = literals,
                                    reflectionOrJniHits = refHits,
                                ),
                            )
                        }
                        lower.endsWith(".xml") -> xmlCount++
                    }
                }
            }
        }

        walk(root, "", 0)

        SourceProjectAnalysisResult(
            projectId = projectId,
            projectName = projectName,
            treeUriString = treeUri.toString(),
            applicationId = appId,
            hasGradleWrapperOrBuild = hasGradle,
            hasR8MinifyEnabled = hasMinify,
            hasResourceShrinking = hasShrinkRes,
            hasProguardRulesFile = hasProguard,
            kotlinFileCount = ktCount,
            javaFileCount = javaCount,
            xmlFileCount = xmlCount,
            detectedPackages = packages.toList().sorted(),
            sourceFiles = sourceFiles,
            sensitiveStringCandidates = sensitiveStrings.toList(),
            entryPointsFromManifest = manifestComponents.toList(),
            analyzedAtMs = System.currentTimeMillis(),
        )
    }

    private fun readTextSafely(context: Context, uri: Uri, maxBytes: Int): String {
        return runCatching {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                val buf = ByteArray(maxBytes)
                val read = stream.read(buf)
                if (read > 0) String(buf, 0, read, Charsets.UTF_8) else ""
            } ?: ""
        }.getOrDefault("")
    }
}
