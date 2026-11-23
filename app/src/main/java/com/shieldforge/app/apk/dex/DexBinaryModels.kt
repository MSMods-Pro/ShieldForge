package com.shieldforge.app.apk.dex

import com.shieldforge.app.core.common.CompatibilityState
import com.shieldforge.app.core.common.ComponentStatus
import kotlinx.serialization.Serializable

@Serializable
enum class StringSensitivity {
    NORMAL,
    URL_OR_ENDPOINT,
    POTENTIAL_SECRET_OR_KEY,
    CRYPTO_OR_SQL,
    REFLECTION_OR_JNI,
    FILE_OR_PACKAGE_REF,
}

@Serializable
data class DexStringItem(
    val id: String,
    val dexFileName: String,
    val index: Int,
    val value: String,
    val sensitivity: StringSensitivity,
    val isSourceFileTag: Boolean,
    val referencedByClasses: List<String> = emptyList(),
    val status: ComponentStatus = ComponentStatus.SELECTABLE,
)

@Serializable
data class DexMethodItem(
    val id: String,
    val dexFileName: String,
    val methodIdx: Int,
    val declaringClass: String,
    val name: String,
    val returnType: String,
    val parameterTypes: List<String>,
    val signature: String,
    val accessFlags: Int,
    val modifiers: List<String>,
    val isDirect: Boolean,
    val isNative: Boolean,
    val isSynthetic: Boolean,
    val compatibility: CompatibilityState,
    val status: ComponentStatus,
)

@Serializable
data class DexFieldItem(
    val id: String,
    val dexFileName: String,
    val fieldIdx: Int,
    val declaringClass: String,
    val name: String,
    val fieldType: String,
    val accessFlags: Int,
    val modifiers: List<String>,
    val isStatic: Boolean,
    val isSynthetic: Boolean,
    val compatibility: CompatibilityState,
    val status: ComponentStatus,
)

@Serializable
data class DexClassItem(
    val id: String,
    val dexFileName: String,
    val classDefIndex: Int,
    val descriptor: String,
    val className: String,
    val simpleName: String,
    val packageName: String,
    val superClass: String,
    val interfaces: List<String>,
    val sourceFile: String?,
    val sourceFileIdx: Int,
    val accessFlags: Int,
    val modifiers: List<String>,
    val methodCount: Int,
    val fieldCount: Int,
    val hasReflectionIndicators: Boolean,
    val hasJniIndicators: Boolean,
    val isManifestComponent: Boolean,
    val compatibility: CompatibilityState,
    val status: ComponentStatus,
)

@Serializable
data class DexPackageNode(
    val packageName: String,
    val dexFiles: List<String>,
    val classCount: Int,
    val methodCount: Int,
    val fieldCount: Int,
    val stringCount: Int,
    val hasCautionComponents: Boolean,
)

@Serializable
data class DexFileSummary(
    val fileName: String,
    val version: String,
    val isSupportedVersion: Boolean,
    val fileSizeBytes: Int,
    val adler32Valid: Boolean,
    val sha1Valid: Boolean,
    val sha256Hex: String,
    val stringCount: Int,
    val typeCount: Int,
    val protoCount: Int,
    val fieldCount: Int,
    val methodCount: Int,
    val classCount: Int,
    val packageCount: Int,
    val compatibility: CompatibilityState,
    val status: ComponentStatus,
    val errorNote: String? = null,
)

@Serializable
data class DexAnalysisBundle(
    val dexFiles: List<DexFileSummary>,
    val packages: List<DexPackageNode>,
    val classes: List<DexClassItem>,
    val methods: List<DexMethodItem>,
    val fields: List<DexFieldItem>,
    val strings: List<DexStringItem>,
    val crossDexReferences: List<String>,
)
