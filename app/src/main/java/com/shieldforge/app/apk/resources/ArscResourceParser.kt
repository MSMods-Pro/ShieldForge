package com.shieldforge.app.apk.resources

import com.shieldforge.app.core.common.CompatibilityState
import com.shieldforge.app.core.common.ComponentStatus
import com.shieldforge.app.core.crypto.CryptoEngine
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.ByteOrder

@Serializable
enum class ResourceCategory(val label: String) {
    XML("XML"),
    DRAWABLE("Drawable"),
    IMAGE("Image"),
    FONT("Font"),
    RAW("Raw"),
    ASSET("Asset"),
    CONFIG("Config"),
    NATIVE_LIB("Native .so"),
    METADATA("Build Metadata"),
    OTHER("Other"),
}

@Serializable
data class ResourceEntryItem(
    val id: String,
    val path: String,
    val category: ResourceCategory,
    val sizeBytes: Long,
    val isCompressed: Boolean,
    val isSensitiveConfig: Boolean,
    val isSafeStrippableMetadata: Boolean,
    val compatibility: CompatibilityState,
    val status: ComponentStatus,
)

@Serializable
data class NativeLibInfo(
    val path: String,
    val abi: String,
    val fileName: String,
    val sizeBytes: Long,
    val isValidElf: Boolean,
    val is64BitElf: Boolean,
    val sha256: String,
)

@Serializable
data class ArscSummary(
    val isValidArsc: Boolean,
    val arscSizeBytes: Int,
    val arscSha256: String,
    val packageCount: Int,
    val resourcePackageName: String,
    val resourceTypeNames: List<String>,
    val resourceKeyCount: Int,
)

@Serializable
data class ResourceAnalysisBundle(
    val arsc: ArscSummary,
    val entries: List<ResourceEntryItem>,
    val nativeLibs: List<NativeLibInfo>,
    val categoryCounts: Map<String, Int>,
)

object ArscResourceParser {
    private const val RES_TABLE_TYPE = 0x0002
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_TABLE_PACKAGE_TYPE = 0x0200

    fun parseArsc(bytes: ByteArray?): ArscSummary {
        if (bytes == null || bytes.size < 12) {
            return ArscSummary(
                isValidArsc = false,
                arscSizeBytes = bytes?.size ?: 0,
                arscSha256 = bytes?.let { CryptoEngine.sha256Hex(it) } ?: "",
                packageCount = 0,
                resourcePackageName = "",
                resourceTypeNames = emptyList(),
                resourceKeyCount = 0,
            )
        }
        val sha = CryptoEngine.sha256Hex(bytes)
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val type = buf.getShort(0).toInt() and 0xFFFF
        val headerSize = buf.getShort(2).toInt() and 0xFFFF
        if (type != RES_TABLE_TYPE || headerSize < 12) {
            return ArscSummary(false, bytes.size, sha, 0, "", emptyList(), 0)
        }
        val packageCount = buf.getInt(8)
        var pkgName = ""
        val typeNames = mutableListOf<String>()
        var keyCount = 0

        var offset = headerSize
        while (offset + 8 <= bytes.size) {
            val cType = buf.getShort(offset).toInt() and 0xFFFF
            val cHeaderSize = buf.getShort(offset + 2).toInt() and 0xFFFF
            val cSize = buf.getInt(offset + 4)
            if (cSize < 8 || offset + cSize > bytes.size) break

            if (cType == RES_TABLE_PACKAGE_TYPE && offset + 288 <= bytes.size) {
                val nameBytes = bytes.copyOfRange(offset + 12, offset + 268)
                pkgName = String(nameBytes, Charsets.UTF_16LE).substringBefore('\u0000')
                val typeStringsRel = buf.getInt(offset + 268)
                val keyStringsRel = buf.getInt(offset + 276)
                if (typeStringsRel > 0 && offset + typeStringsRel + 28 <= bytes.size) {
                    typeNames.addAll(parsePoolStrings(bytes, offset + typeStringsRel))
                }
                if (keyStringsRel > 0 && offset + keyStringsRel + 28 <= bytes.size) {
                    keyCount += buf.getInt(offset + keyStringsRel + 8)
                }
            }
            offset += cSize
        }

        return ArscSummary(
            isValidArsc = true,
            arscSizeBytes = bytes.size,
            arscSha256 = sha,
            packageCount = packageCount,
            resourcePackageName = pkgName,
            resourceTypeNames = typeNames.distinct(),
            resourceKeyCount = keyCount,
        )
    }

    fun classifyEntry(path: String, sizeBytes: Long, isCompressed: Boolean): ResourceEntryItem {
        val lower = path.lowercase()
        val category = when {
            lower.startsWith("lib/") && lower.endsWith(".so") -> ResourceCategory.NATIVE_LIB
            lower.startsWith("assets/") && (lower.endsWith(".json") || lower.endsWith(".properties") ||
                lower.endsWith(".conf") || lower.endsWith(".yml") || lower.endsWith(".yaml")) ->
                ResourceCategory.CONFIG
            lower.startsWith("assets/") -> ResourceCategory.ASSET
            lower.startsWith("res/font/") || lower.endsWith(".ttf") || lower.endsWith(".otf") ->
                ResourceCategory.FONT
            lower.startsWith("res/raw/") -> ResourceCategory.RAW
            lower.startsWith("res/drawable") && (lower.endsWith(".png") || lower.endsWith(".webp") ||
                lower.endsWith(".jpg") || lower.endsWith(".jpeg")) -> ResourceCategory.IMAGE
            lower.startsWith("res/mipmap") -> ResourceCategory.IMAGE
            lower.startsWith("res/drawable") -> ResourceCategory.DRAWABLE
            lower.startsWith("res/xml/") || lower.endsWith(".xml") -> ResourceCategory.XML
            lower.endsWith(".kotlin_builtins") || lower.endsWith(".kotlin_module") ||
                (lower.startsWith("meta-inf/") && lower.endsWith(".version")) ||
                lower == "debug-probers.kt" -> ResourceCategory.METADATA
            else -> ResourceCategory.OTHER
        }

        val isSensitiveCfg = category == ResourceCategory.CONFIG ||
            (category == ResourceCategory.RAW && (lower.contains("config") || lower.contains("secret") || lower.contains("env")))
        val isSafeMeta = category == ResourceCategory.METADATA

        val (compat, status) = when {
            isSafeMeta -> CompatibilityState.COMPATIBLE to ComponentStatus.TRANSFORMABLE
            category == ResourceCategory.ASSET || category == ResourceCategory.CONFIG ->
                CompatibilityState.COMPATIBLE to ComponentStatus.TRANSFORMABLE
            category == ResourceCategory.NATIVE_LIB ->
                CompatibilityState.CAUTION_JNI to ComponentStatus.INSPECTABLE
            else -> CompatibilityState.COMPATIBLE to ComponentStatus.SELECTABLE
        }

        return ResourceEntryItem(
            id = "RES#$path",
            path = path,
            category = category,
            sizeBytes = sizeBytes,
            isCompressed = isCompressed,
            isSensitiveConfig = isSensitiveCfg,
            isSafeStrippableMetadata = isSafeMeta,
            compatibility = compat,
            status = status,
        )
    }

    fun inspectNativeLib(path: String, bytes: ByteArray): NativeLibInfo {
        val parts = path.split('/')
        val abi = parts.getOrNull(1) ?: "unknown"
        val fileName = parts.lastOrNull() ?: path
        val isElf = bytes.size >= 5 &&
            bytes[0] == 0x7F.toByte() &&
            bytes[1] == 'E'.code.toByte() &&
            bytes[2] == 'L'.code.toByte() &&
            bytes[3] == 'F'.code.toByte()
        val is64 = isElf && bytes[4].toInt() == 2
        return NativeLibInfo(
            path = path,
            abi = abi,
            fileName = fileName,
            sizeBytes = bytes.size.toLong(),
            isValidElf = isElf,
            is64BitElf = is64,
            sha256 = CryptoEngine.sha256Hex(bytes),
        )
    }

    private fun parsePoolStrings(bytes: ByteArray, poolOffset: Int): List<String> {
        if (poolOffset + 28 > bytes.size) return emptyList()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val type = buf.getShort(poolOffset).toInt() and 0xFFFF
        if (type != RES_STRING_POOL_TYPE) return emptyList()
        val chunkSize = buf.getInt(poolOffset + 4)
        val stringCount = buf.getInt(poolOffset + 8)
        val flags = buf.getInt(poolOffset + 16)
        val stringsStart = buf.getInt(poolOffset + 20)
        val isUtf8 = (flags and 0x100) != 0
        val dataStart = poolOffset + stringsStart
        val end = (poolOffset + chunkSize).coerceAtMost(bytes.size)

        return (0 until stringCount.coerceAtMost(200)).map { i ->
            val offPos = poolOffset + 28 + i * 4
            if (offPos + 4 > end) return@map ""
            val pos = dataStart + buf.getInt(offPos)
            if (pos < 0 || pos >= end) return@map ""
            if (isUtf8) {
                var p = pos
                if (p < end && (bytes[p].toInt() and 0x80) != 0) p += 2 else p += 1
                var len = 0
                if (p < end) {
                    val b0 = bytes[p++].toInt() and 0xFF
                    len = if ((b0 and 0x80) != 0 && p < end) ((b0 and 0x7F) shl 8) or (bytes[p++].toInt() and 0xFF) else b0
                }
                String(bytes, p, len.coerceAtMost((end - p).coerceAtLeast(0)), Charsets.UTF_8)
            } else {
                if (pos + 2 > end) return@map ""
                val charLen = buf.getShort(pos).toInt() and 0x7FFF
                val byteLen = (charLen * 2).coerceAtMost((end - (pos + 2)).coerceAtLeast(0))
                String(bytes, pos + 2, byteLen, Charsets.UTF_16LE)
            }
        }
    }
}
