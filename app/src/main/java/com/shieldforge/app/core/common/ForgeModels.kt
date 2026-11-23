package com.shieldforge.app.core.common

import kotlinx.serialization.Serializable

@Serializable
enum class ProjectMode {
    PRECOMPILED_APK,
    SOURCE_PROJECT,
}

@Serializable
enum class ComponentType {
    APPLICATION,
    DEX_FILE,
    PACKAGE,
    CLASS,
    METHOD,
    FIELD,
    STRING,
    RESOURCE,
    MANIFEST_COMPONENT,
    MANIFEST_PERMISSION,
    NATIVE_LIB,
}

@Serializable
enum class ComponentStatus {
    INSPECTABLE,
    SELECTABLE,
    TRANSFORMABLE,
    VERIFIED,
    UNSUPPORTED_PRECOMPILED,
    SOURCE_PROJECT_ONLY,
}

@Serializable
enum class CompatibilityState {
    COMPATIBLE,
    CAUTION_REFLECTION,
    CAUTION_FRAMEWORK_ENTRY,
    CAUTION_JNI,
    REQUIRES_SOURCE_R8,
    INCOMPATIBLE,
}

@Serializable
enum class ProtectionModuleId(
    val displayName: String,
    val codeName: String,
    val summary: String,
) {
    STRING_FORGE(
        displayName = "StringForge",
        codeName = "MOD-STR",
        summary = "DEX string inventory, sensitive classification, AES-256-GCM vault generation & debug-name stripping",
    ),
    MANIFEST_FORGE(
        displayName = "ManifestForge",
        codeName = "MOD-MAN",
        summary = "AXML manifest audit, safe attribute hardening (debuggable/allowBackup) & SHA-256 seal",
    ),
    RESOURCE_FORGE(
        displayName = "ResourceForge",
        codeName = "MOD-RES",
        summary = "ARSC inventory, metadata stripping, AES-GCM asset sealing & reference integrity",
    ),
    DEX_FORGE(
        displayName = "DEXForge",
        codeName = "MOD-DEX",
        summary = "Multidex inspection, debug source-file stripping & R8/ProGuard hardening rules",
    ),
    INTEGRITY_FORGE(
        displayName = "IntegrityForge",
        codeName = "MOD-INT",
        summary = "DEX/Manifest/ARSC SHA-256 verification, build fingerprint & runtime integrity guard",
    ),
    CONFIG_FORGE(
        displayName = "ConfigForge",
        codeName = "MOD-CFG",
        summary = "Sensitive configuration audit, Keystore-backed AES-GCM sealing & lifecycle guard",
    ),
    BUILD_GUARD(
        displayName = "BuildGuard",
        codeName = "MOD-BLD",
        summary = "Deterministic ZIP reconstruction, 4-byte alignment, v1+v2 APK signing & post-build validation",
    ),
}

@Serializable
enum class EngineExecutionState {
    IDLE,
    READY,
    RUNNING,
    SUCCEEDED,
    PARTIAL_WITH_WARNINGS,
    SKIPPED,
    UNSUPPORTED,
    FAILED,
}

@Serializable
data class EngineExecutionResult(
    val moduleId: ProtectionModuleId,
    val state: EngineExecutionState,
    val processedCount: Int = 0,
    val skippedCount: Int = 0,
    val unsupportedCount: Int = 0,
    val warnings: List<String> = emptyList(),
    val artifactsProduced: List<String> = emptyList(),
    val summary: String,
    val durationMs: Long = 0L,
)

@Serializable
enum class LogLevel {
    INFO,
    STAGE,
    WARN,
    ERROR,
    VERIFIED,
}

@Serializable
data class LogEntry(
    val timestampMs: Long = System.currentTimeMillis(),
    val stage: String,
    val level: LogLevel,
    val message: String,
)

@Serializable
data class ApoStepState(
    val index: Int,
    val title: String,
    val completed: Boolean = false,
    val active: Boolean = false,
    val failed: Boolean = false,
    val detail: String = "",
)

@Serializable
data class BuildFingerprint(
    val buildId: String,
    val timestampEpochMs: Long,
    val inputSha256: String,
    val outputSha256: String,
    val manifestSha256: String,
    val arscSha256: String,
    val dexDigests: Map<String, String>,
    val signingCertSha256: String,
)

@Serializable
data class DependencyConflict(
    val id: String,
    val componentId: String,
    val componentLabel: String,
    val reason: String,
    val severity: String, // "BLOCKING" or "WARNING"
    val resolution: String,
)

@Serializable
data class ProtectionReport(
    val reportId: String,
    val projectId: String,
    val projectName: String,
    val mode: ProjectMode,
    val profileName: String,
    val generatedAtMs: Long,
    val buildDurationMs: Long,
    val inputPackageName: String,
    val inputVersionName: String,
    val inputVersionCode: Long,
    val inputSizeBytes: Long,
    val outputSizeBytes: Long,
    val outputPath: String,
    val originalDexInventory: List<String>,
    val selectedComponentCount: Int,
    val selectedModules: List<ProtectionModuleId>,
    val engineResults: List<EngineExecutionResult>,
    val dependencyConflicts: List<DependencyConflict>,
    val validationPassed: Boolean,
    val validationDetails: List<String>,
    val signingSummary: String,
    val buildFingerprint: BuildFingerprint?,
    val notes: List<String>,
)

fun formatByteSize(bytes: Long): String {
    if (bytes < 1024L) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024.0) return String.format(java.util.Locale.US, "%.1f KB", kb)
    val mb = kb / 1024.0
    return String.format(java.util.Locale.US, "%.2f MB", mb)
}
