package com.shieldforge.app.apk.manifest

import com.shieldforge.app.core.crypto.CryptoEngine
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.ByteOrder

@Serializable
data class ManifestComponentEntry(
    val type: String, // Activity, Service, Receiver, Provider
    val name: String,
    val exported: Boolean?,
    val permission: String?,
    val intentActions: List<String> = emptyList(),
)

@Serializable
data class ManifestAuditFinding(
    val id: String,
    val severity: String, // HIGH, MEDIUM, INFO
    val title: String,
    val detail: String,
)

@Serializable
data class ManifestAnalysisResult(
    val packageName: String,
    val versionName: String,
    val versionCode: Long,
    val minSdk: Int?,
    val targetSdk: Int?,
    val applicationLabel: String?,
    val applicationClass: String?,
    val isDebuggable: Boolean,
    val allowBackup: Boolean?,
    val usesCleartextTraffic: Boolean?,
    val permissions: List<String>,
    val components: List<ManifestComponentEntry>,
    val metadataKeys: List<String>,
    val findings: List<ManifestAuditFinding>,
    val manifestSha256: String,
    val isValidAxml: Boolean,
)

object BinaryManifestParser {
    private const val CHUNK_AXML_FILE = 0x00080003
    private const val CHUNK_STRING_POOL = 0x001C0001
    private const val CHUNK_RESOURCE_MAP = 0x00080180
    private const val CHUNK_XML_START_ELEMENT = 0x00100102
    private const val CHUNK_XML_END_ELEMENT = 0x00100103

    private const val TYPE_INT_DEC = 0x10
    private const val TYPE_INT_HEX = 0x11
    private const val TYPE_INT_BOOLEAN = 0x12
    private const val TYPE_STRING = 0x03

    private const val ATTR_RES_MIN_SDK = 0x0101020c
    private const val ATTR_RES_TARGET_SDK = 0x01010270
    private const val ATTR_RES_VERSION_CODE = 0x0101021b
    private const val ATTR_RES_VERSION_NAME = 0x0101021c
    private const val ATTR_RES_DEBUGGABLE = 0x0101000f
    private const val ATTR_RES_ALLOW_BACKUP = 0x01010280
    private const val ATTR_RES_CLEARTEXT = 0x010104ec
    private const val ATTR_RES_EXPORTED = 0x01010010
    private const val ATTR_RES_NAME = 0x01010003
    private const val ATTR_RES_LABEL = 0x01010001
    private const val ATTR_RES_PERMISSION = 0x01010006

    fun parse(bytes: ByteArray): ManifestAnalysisResult {
        val sha256 = CryptoEngine.sha256Hex(bytes)
        if (bytes.size < 8) {
            return invalidResult(sha256)
        }
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val fileType = buf.getInt(0)
        if (fileType != CHUNK_AXML_FILE) {
            return invalidResult(sha256)
        }

        var strings = emptyList<String>()
        var resIds = emptyList<Int>()

        var packageName = ""
        var versionName = ""
        var versionCode = 0L
        var minSdk: Int? = null
        var targetSdk: Int? = null
        var appLabel: String? = null
        var appClass: String? = null
        var isDebuggable = false
        var allowBackup: Boolean? = null
        var usesCleartext: Boolean? = null

        val permissions = mutableListOf<String>()
        val components = mutableListOf<ManifestComponentEntry>()
        val metadataKeys = mutableListOf<String>()
        var activeComponent: ManifestComponentEntry? = null
        val activeIntentActions = mutableListOf<String>()

        var offset = 8
        while (offset + 8 <= bytes.size) {
            val chunkType = buf.getInt(offset)
            val chunkSize = buf.getInt(offset + 4)
            if (chunkSize < 8 || offset + chunkSize > bytes.size) break

            when (chunkType) {
                CHUNK_STRING_POOL -> {
                    strings = parseStringPool(bytes, offset, chunkSize)
                }
                CHUNK_RESOURCE_MAP -> {
                    val count = (chunkSize - 8) / 4
                    resIds = (0 until count).map { i -> buf.getInt(offset + 8 + i * 4) }
                }
                CHUNK_XML_START_ELEMENT -> {
                    if (offset + 36 <= bytes.size) {
                        val nameIdx = buf.getInt(offset + 20)
                        val attrStart = buf.getShort(offset + 24).toInt() and 0xFFFF
                        val attrSize = buf.getShort(offset + 26).toInt() and 0xFFFF
                        val attrCount = buf.getShort(offset + 28).toInt() and 0xFFFF
                        val tagName = strings.getOrElse(nameIdx) { "" }

                        val attrsOffset = offset + 16 + attrStart
                        val attrValues = mutableMapOf<String, Pair<Int, Int>>()
                        val attrResValues = mutableMapOf<Int, Pair<Int, Int>>()

                        for (a in 0 until attrCount) {
                            val aOff = attrsOffset + a * attrSize
                            if (aOff + 20 > bytes.size) break
                            val aNameIdx = buf.getInt(aOff + 4)
                            val aRawValIdx = buf.getInt(aOff + 8)
                            val aDataType = (buf.get(aOff + 15).toInt() and 0xFF)
                            val aData = buf.getInt(aOff + 16)
                            val aName = strings.getOrElse(aNameIdx) { "" }
                            val resId = resIds.getOrNull(aNameIdx) ?: 0
                            attrValues[aName] = aDataType to aData
                            if (resId != 0) attrResValues[resId] = aDataType to aData
                            if (aName == "package" && aRawValIdx >= 0) {
                                packageName = strings.getOrElse(aRawValIdx) { packageName }
                            }
                        }

                        fun resolveStr(name: String, resId: Int? = null): String? {
                            val pair = (if (resId != null) attrResValues[resId] else null) ?: attrValues[name]
                            return if (pair != null && pair.first == TYPE_STRING) {
                                strings.getOrNull(pair.second)
                            } else null
                        }

                        fun resolveInt(name: String, resId: Int? = null): Int? {
                            val pair = (if (resId != null) attrResValues[resId] else null) ?: attrValues[name]
                            return if (pair != null && (pair.first == TYPE_INT_DEC || pair.first == TYPE_INT_HEX)) {
                                pair.second
                            } else null
                        }

                        fun resolveBool(name: String, resId: Int? = null): Boolean? {
                            val pair = (if (resId != null) attrResValues[resId] else null) ?: attrValues[name]
                            return if (pair != null && pair.first == TYPE_INT_BOOLEAN) {
                                pair.second != 0
                            } else null
                        }

                        when (tagName) {
                            "manifest" -> {
                                resolveStr("package")?.let { packageName = it }
                                resolveStr("versionName", ATTR_RES_VERSION_NAME)?.let { versionName = it }
                                resolveInt("versionCode", ATTR_RES_VERSION_CODE)?.let { versionCode = it.toLong() }
                            }
                            "uses-sdk" -> {
                                minSdk = resolveInt("minSdkVersion", ATTR_RES_MIN_SDK) ?: minSdk
                                targetSdk = resolveInt("targetSdkVersion", ATTR_RES_TARGET_SDK) ?: targetSdk
                            }
                            "uses-permission", "uses-permission-sdk-23" -> {
                                resolveStr("name", ATTR_RES_NAME)?.let { permissions.add(it) }
                            }
                            "application" -> {
                                appLabel = resolveStr("label", ATTR_RES_LABEL)
                                appClass = resolveStr("name", ATTR_RES_NAME)
                                isDebuggable = resolveBool("debuggable", ATTR_RES_DEBUGGABLE) ?: false
                                allowBackup = resolveBool("allowBackup", ATTR_RES_ALLOW_BACKUP)
                                usesCleartext = resolveBool("usesCleartextTraffic", ATTR_RES_CLEARTEXT)
                            }
                            "activity", "activity-alias", "service", "receiver", "provider" -> {
                                val rawName = resolveStr("name", ATTR_RES_NAME) ?: "unnamed"
                                val fullName = when {
                                    rawName.startsWith(".") && packageName.isNotEmpty() -> "$packageName$rawName"
                                    !rawName.contains(".") && packageName.isNotEmpty() -> "$packageName.$rawName"
                                    else -> rawName
                                }
                                activeIntentActions.clear()
                                activeComponent = ManifestComponentEntry(
                                    type = tagName.replaceFirstChar { it.uppercase() },
                                    name = fullName,
                                    exported = resolveBool("exported", ATTR_RES_EXPORTED),
                                    permission = resolveStr("permission", ATTR_RES_PERMISSION),
                                )
                            }
                            "action" -> {
                                resolveStr("name", ATTR_RES_NAME)?.let { activeIntentActions.add(it) }
                            }
                            "meta-data" -> {
                                resolveStr("name", ATTR_RES_NAME)?.let { metadataKeys.add(it) }
                            }
                        }
                    }
                }
                CHUNK_XML_END_ELEMENT -> {
                    if (offset + 24 <= bytes.size) {
                        val nameIdx = buf.getInt(offset + 20)
                        val tagName = strings.getOrElse(nameIdx) { "" }
                        if (tagName in setOf("activity", "activity-alias", "service", "receiver", "provider")) {
                            activeComponent?.let { comp ->
                                components.add(comp.copy(intentActions = activeIntentActions.toList()))
                            }
                            activeComponent = null
                            activeIntentActions.clear()
                        }
                    }
                }
            }
            offset += chunkSize
        }

        val findings = buildList {
            if (isDebuggable) {
                add(
                    ManifestAuditFinding(
                        id = "MAN_DEBUGGABLE",
                        severity = "HIGH",
                        title = "android:debuggable=\"true\" detected",
                        detail = "Allows debugger attachment and runtime memory inspection. ManifestForge can harden this attribute in AXML.",
                    ),
                )
            }
            if (allowBackup == true) {
                add(
                    ManifestAuditFinding(
                        id = "MAN_ALLOW_BACKUP",
                        severity = "MEDIUM",
                        title = "android:allowBackup=\"true\" enabled",
                        detail = "Application data may be backed up via adb/cloud unless restricted with dataExtractionRules.",
                    ),
                )
            }
            if (usesCleartext == true) {
                add(
                    ManifestAuditFinding(
                        id = "MAN_CLEARTEXT",
                        severity = "MEDIUM",
                        title = "Cleartext HTTP traffic allowed",
                        detail = "usesCleartextTraffic=\"true\" permits unencrypted HTTP transport.",
                    ),
                )
            }
            val unguardedExported = components.count { it.exported == true && it.permission == null }
            if (unguardedExported > 0) {
                add(
                    ManifestAuditFinding(
                        id = "MAN_EXPORTED",
                        severity = "INFO",
                        title = "$unguardedExported exported component(s) without explicit permission",
                        detail = "Verify exported Activities/Services/Receivers are intentionally reachable by external apps.",
                    ),
                )
            }
            if (metadataKeys.isNotEmpty()) {
                add(
                    ManifestAuditFinding(
                        id = "MAN_METADATA",
                        severity = "INFO",
                        title = "${metadataKeys.size} <meta-data> entries exposed in manifest",
                        detail = "Review metadata entries to ensure no sensitive API tokens or internal flags are exposed.",
                    ),
                )
            }
        }

        return ManifestAnalysisResult(
            packageName = packageName.ifBlank { "unknown.package" },
            versionName = versionName.ifBlank { "1.0" },
            versionCode = versionCode,
            minSdk = minSdk,
            targetSdk = targetSdk,
            applicationLabel = appLabel,
            applicationClass = appClass,
            isDebuggable = isDebuggable,
            allowBackup = allowBackup,
            usesCleartextTraffic = usesCleartext,
            permissions = permissions.distinct(),
            components = components,
            metadataKeys = metadataKeys.distinct(),
            findings = findings,
            manifestSha256 = sha256,
            isValidAxml = packageName.isNotBlank(),
        )
    }

    /**
     * Safely flips existing boolean attributes (debuggable=false, allowBackup=false) in binary AXML
     * without shifting any chunk offsets or breaking resource tables.
     */
    fun hardenApplicationBooleansInPlace(
        bytes: ByteArray,
        forceDebuggableFalse: Boolean,
        forceAllowBackupFalse: Boolean,
    ): Pair<ByteArray, List<String>> {
        if (bytes.size < 8) return bytes to emptyList()
        val out = bytes.copyOf()
        val buf = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        if (buf.getInt(0) != CHUNK_AXML_FILE) return bytes to emptyList()

        var strings = emptyList<String>()
        var resIds = emptyList<Int>()
        val applied = mutableListOf<String>()

        var offset = 8
        while (offset + 8 <= out.size) {
            val chunkType = buf.getInt(offset)
            val chunkSize = buf.getInt(offset + 4)
            if (chunkSize < 8 || offset + chunkSize > out.size) break

            when (chunkType) {
                CHUNK_STRING_POOL -> strings = parseStringPool(out, offset, chunkSize)
                CHUNK_RESOURCE_MAP -> {
                    val count = (chunkSize - 8) / 4
                    resIds = (0 until count).map { i -> buf.getInt(offset + 8 + i * 4) }
                }
                CHUNK_XML_START_ELEMENT -> {
                    val nameIdx = buf.getInt(offset + 20)
                    if (strings.getOrNull(nameIdx) == "application") {
                        val attrStart = buf.getShort(offset + 24).toInt() and 0xFFFF
                        val attrSize = buf.getShort(offset + 26).toInt() and 0xFFFF
                        val attrCount = buf.getShort(offset + 28).toInt() and 0xFFFF
                        val attrsOffset = offset + 16 + attrStart
                        for (a in 0 until attrCount) {
                            val aOff = attrsOffset + a * attrSize
                            if (aOff + 20 > out.size) break
                            val aNameIdx = buf.getInt(aOff + 4)
                            val aDataType = buf.get(aOff + 15).toInt() and 0xFF
                            val aData = buf.getInt(aOff + 16)
                            val resId = resIds.getOrNull(aNameIdx) ?: 0
                            val aName = strings.getOrNull(aNameIdx) ?: ""

                            if (forceDebuggableFalse &&
                                (resId == ATTR_RES_DEBUGGABLE || aName == "debuggable") &&
                                aDataType == TYPE_INT_BOOLEAN && aData != 0
                            ) {
                                buf.putInt(aOff + 16, 0)
                                applied.add("Set android:debuggable=false in binary AXML")
                            }
                            if (forceAllowBackupFalse &&
                                (resId == ATTR_RES_ALLOW_BACKUP || aName == "allowBackup") &&
                                aDataType == TYPE_INT_BOOLEAN && aData != 0
                            ) {
                                buf.putInt(aOff + 16, 0)
                                applied.add("Set android:allowBackup=false in binary AXML")
                            }
                        }
                    }
                }
            }
            offset += chunkSize
        }
        return out to applied
    }

    private fun parseStringPool(bytes: ByteArray, offset: Int, chunkSize: Int): List<String> {
        if (offset + 28 > bytes.size) return emptyList()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val stringCount = buf.getInt(offset + 8)
        val flags = buf.getInt(offset + 16)
        val stringsStart = buf.getInt(offset + 20)
        val isUtf8 = (flags and 0x100) != 0
        val poolDataStart = offset + stringsStart
        val chunkEnd = (offset + chunkSize).coerceAtMost(bytes.size)

        return (0 until stringCount.coerceAtMost(50_000)).map { i ->
            val offPos = offset + 28 + i * 4
            if (offPos + 4 > chunkEnd) return@map ""
            val strRelOff = buf.getInt(offPos)
            val pos = poolDataStart + strRelOff
            if (pos < 0 || pos >= chunkEnd) return@map ""
            if (isUtf8) {
                var p = pos
                if (p < chunkEnd && (bytes[p].toInt() and 0x80) != 0) p += 2 else p += 1
                var byteLen = 0
                if (p < chunkEnd) {
                    val b0 = bytes[p++].toInt() and 0xFF
                    byteLen = if ((b0 and 0x80) != 0 && p < chunkEnd) {
                        ((b0 and 0x7F) shl 8) or (bytes[p++].toInt() and 0xFF)
                    } else b0
                }
                val safeLen = byteLen.coerceAtMost((chunkEnd - p).coerceAtLeast(0))
                String(bytes, p, safeLen, Charsets.UTF_8)
            } else {
                if (pos + 2 > chunkEnd) return@map ""
                var charLen = buf.getShort(pos).toInt() and 0xFFFF
                var p = pos + 2
                if ((charLen and 0x8000) != 0 && p + 2 <= chunkEnd) {
                    charLen = ((charLen and 0x7FFF) shl 16) or (buf.getShort(p).toInt() and 0xFFFF)
                    p += 2
                }
                val byteLen = (charLen * 2).coerceAtMost((chunkEnd - p).coerceAtLeast(0))
                String(bytes, p, byteLen, Charsets.UTF_16LE)
            }
        }
    }

    private fun invalidResult(sha256: String) = ManifestAnalysisResult(
        packageName = "invalid.manifest",
        versionName = "-",
        versionCode = 0L,
        minSdk = null,
        targetSdk = null,
        applicationLabel = null,
        applicationClass = null,
        isDebuggable = false,
        allowBackup = null,
        usesCleartextTraffic = null,
        permissions = emptyList(),
        components = emptyList(),
        metadataKeys = emptyList(),
        findings = listOf(
            ManifestAuditFinding(
                id = "MAN_INVALID",
                severity = "HIGH",
                title = "Invalid or non-binary AndroidManifest.xml",
                detail = "Expected Android AXML binary chunk header (0x00080003).",
            ),
        ),
        manifestSha256 = sha256,
        isValidAxml = false,
    )
}
