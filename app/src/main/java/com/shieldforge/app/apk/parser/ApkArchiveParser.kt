package com.shieldforge.app.apk.parser

import com.shieldforge.app.apk.dex.DexAnalysisBundle
import com.shieldforge.app.apk.dex.DexBinaryParser
import com.shieldforge.app.apk.manifest.BinaryManifestParser
import com.shieldforge.app.apk.manifest.ManifestAnalysisResult
import com.shieldforge.app.apk.resources.ArscResourceParser
import com.shieldforge.app.apk.resources.NativeLibInfo
import com.shieldforge.app.apk.resources.ResourceAnalysisBundle
import com.shieldforge.app.apk.resources.ResourceEntryItem
import com.shieldforge.app.apk.signing.ApkSignatureVerification
import com.shieldforge.app.apk.signing.ApkSignerEngine
import com.shieldforge.app.core.crypto.CryptoEngine
import kotlinx.serialization.Serializable
import java.io.File
import java.util.zip.ZipFile

@Serializable
data class ApkAnalysisResult(
    val projectId: String,
    val fileName: String,
    val workspaceApkPath: String,
    val fileSizeBytes: Long,
    val apkSha256: String,
    val totalZipEntries: Int,
    val manifest: ManifestAnalysisResult,
    val dexBundle: DexAnalysisBundle,
    val resourceBundle: ResourceAnalysisBundle,
    val signatureInfo: ApkSignatureVerification,
    val analyzedAtMs: Long,
    val iconPngBytesBase64: String? = null,
)

object ApkArchiveParser {
    fun analyzeApk(
        projectId: String,
        displayFileName: String,
        apkFile: File,
    ): ApkAnalysisResult {
        val apkBytes = apkFile.readBytes()
        val apkSha256 = CryptoEngine.sha256Hex(apkBytes)

        var manifestBytes: ByteArray? = null
        var arscBytes: ByteArray? = null
        val dexMap = linkedMapOf<String, ByteArray>()
        val resEntries = mutableListOf<ResourceEntryItem>()
        val nativeLibs = mutableListOf<NativeLibInfo>()
        var iconCandidate: ByteArray? = null
        var iconCandidateSize = 0
        var totalEntries = 0

        ZipFile(apkFile).use { zip ->
            val entries = zip.entries().toList()
            totalEntries = entries.size
            for (entry in entries) {
                if (entry.isDirectory) continue
                val name = entry.name
                when {
                    name == "AndroidManifest.xml" -> {
                        manifestBytes = zip.getInputStream(entry).use { it.readBytes() }
                    }
                    name == "resources.arsc" -> {
                        arscBytes = zip.getInputStream(entry).use { it.readBytes() }
                    }
                    name.startsWith("classes") && name.endsWith(".dex") && !name.contains("/") -> {
                        dexMap[name] = zip.getInputStream(entry).use { it.readBytes() }
                    }
                    name.startsWith("lib/") && name.endsWith(".so") -> {
                        val libBytes = zip.getInputStream(entry).use { it.readBytes() }
                        nativeLibs.add(ArscResourceParser.inspectNativeLib(name, libBytes))
                        resEntries.add(
                            ArscResourceParser.classifyEntry(
                                path = name,
                                sizeBytes = entry.size.coerceAtLeast(libBytes.size.toLong()),
                                isCompressed = entry.method != java.util.zip.ZipEntry.STORED,
                            ),
                        )
                    }
                    else -> {
                        if (!name.startsWith("META-INF/") || name.endsWith(".version") || name.endsWith(".kotlin_module")) {
                            resEntries.add(
                                ArscResourceParser.classifyEntry(
                                    path = name,
                                    sizeBytes = entry.size.coerceAtLeast(0L),
                                    isCompressed = entry.method != java.util.zip.ZipEntry.STORED,
                                ),
                            )
                        }
                        if ((name.contains("ic_launcher") || name.contains("app_icon")) &&
                            (name.endsWith(".png") || name.endsWith(".webp")) &&
                            !name.contains("_round")
                        ) {
                            val candidate = zip.getInputStream(entry).use { it.readBytes() }
                            if (candidate.size > iconCandidateSize && candidate.size < 512_000) {
                                iconCandidate = candidate
                                iconCandidateSize = candidate.size
                            }
                        }
                    }
                }
            }
        }

        val manifestResult = manifestBytes?.let { BinaryManifestParser.parse(it) }
            ?: BinaryManifestParser.parse(ByteArray(0))

        val manifestClasses = manifestResult.components.map { it.name }.toSet()
        val dexBundle = DexBinaryParser.analyzeAllDex(dexMap, manifestClasses)
        val arscSummary = ArscResourceParser.parseArsc(arscBytes)
        val categoryCounts = resEntries.groupingBy { it.category.label }.eachCount()
        val resourceBundle = ResourceAnalysisBundle(
            arsc = arscSummary,
            entries = resEntries.sortedBy { it.path },
            nativeLibs = nativeLibs.sortedBy { it.path },
            categoryCounts = categoryCounts,
        )
        val sigInfo = ApkSignerEngine.inspectApkSignatures(apkFile)

        val iconBase64 = iconCandidate?.let {
            CryptoEngine.base64Encode(it)
        }

        return ApkAnalysisResult(
            projectId = projectId,
            fileName = displayFileName,
            workspaceApkPath = apkFile.absolutePath,
            fileSizeBytes = apkFile.length(),
            apkSha256 = apkSha256,
            totalZipEntries = totalEntries,
            manifest = manifestResult,
            dexBundle = dexBundle,
            resourceBundle = resourceBundle,
            signatureInfo = sigInfo,
            analyzedAtMs = System.currentTimeMillis(),
            iconPngBytesBase64 = iconBase64,
        )
    }
}
