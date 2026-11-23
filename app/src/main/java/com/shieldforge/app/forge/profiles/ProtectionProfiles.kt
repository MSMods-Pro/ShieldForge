package com.shieldforge.app.forge.profiles

import com.shieldforge.app.core.common.ComponentProtectionOverride
import com.shieldforge.app.core.common.ProtectionModuleId
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
data class ProtectionEngineOptions(
    val stripDexSourceFileMetadata: Boolean = true,
    val sealSensitiveStringsToVault: Boolean = true,
    val hardenManifestDebuggable: Boolean = true,
    val hardenManifestAllowBackup: Boolean = false,
    val stripBuildMetadataEntries: Boolean = true,
    val encryptSelectedConfigAssets: Boolean = true,
    val embedIntegrityManifest: Boolean = true,
    val generateSourceR8Rules: Boolean = true,
    val enableAggressiveRepackagingInSource: Boolean = false,
)

@Serializable
data class ProtectionProfile(
    val id: String,
    val name: String,
    val description: String,
    val enabledModules: Set<ProtectionModuleId>,
    val options: ProtectionEngineOptions = ProtectionEngineOptions(),
    val perDexOverrides: Map<String, Set<ProtectionModuleId>> = emptyMap(),
    val isBuiltIn: Boolean = true,
) {
    fun resolveModulesForComponent(
        dexFileName: String?,
        componentOverride: ComponentProtectionOverride?,
    ): Set<ProtectionModuleId> {
        if (componentOverride != null) {
            if (componentOverride.excludeFromTransformation) return emptySet()
            if (!componentOverride.inheritGlobal) return componentOverride.enabledModules
        }
        if (dexFileName != null && perDexOverrides.containsKey(dexFileName)) {
            return perDexOverrides[dexFileName].orEmpty()
        }
        return enabledModules
    }
}

object ProtectionProfilesCatalog {
    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
    }

    val builtInProfiles: List<ProtectionProfile> = listOf(
        ProtectionProfile(
            id = "basic_shield",
            name = "Basic Shield",
            description = "Integrity verification, manifest audit/seal, and BuildGuard dual v1+v2 re-signing.",
            enabledModules = setOf(
                ProtectionModuleId.MANIFEST_FORGE,
                ProtectionModuleId.INTEGRITY_FORGE,
                ProtectionModuleId.BUILD_GUARD,
            ),
            options = ProtectionEngineOptions(
                stripDexSourceFileMetadata = false,
                sealSensitiveStringsToVault = false,
                hardenManifestDebuggable = true,
                hardenManifestAllowBackup = false,
                stripBuildMetadataEntries = false,
                encryptSelectedConfigAssets = false,
                embedIntegrityManifest = true,
                generateSourceR8Rules = true,
            ),
        ),
        ProtectionProfile(
            id = "advanced_shield",
            name = "Advanced Shield",
            description = "Adds DEX source-file metadata stripping and StringForge sensitive literal vaulting.",
            enabledModules = setOf(
                ProtectionModuleId.STRING_FORGE,
                ProtectionModuleId.MANIFEST_FORGE,
                ProtectionModuleId.DEX_FORGE,
                ProtectionModuleId.INTEGRITY_FORGE,
                ProtectionModuleId.BUILD_GUARD,
            ),
            options = ProtectionEngineOptions(
                stripDexSourceFileMetadata = true,
                sealSensitiveStringsToVault = true,
                hardenManifestDebuggable = true,
                hardenManifestAllowBackup = false,
                stripBuildMetadataEntries = true,
                encryptSelectedConfigAssets = false,
                embedIntegrityManifest = true,
                generateSourceR8Rules = true,
            ),
        ),
        ProtectionProfile(
            id = "professional_shield",
            name = "Professional Shield",
            description = "Full 7-engine FORGE-X orchestration with ConfigForge AES-GCM sealing and ResourceForge hygiene.",
            enabledModules = ProtectionModuleId.entries.toSet(),
            options = ProtectionEngineOptions(
                stripDexSourceFileMetadata = true,
                sealSensitiveStringsToVault = true,
                hardenManifestDebuggable = true,
                hardenManifestAllowBackup = true,
                stripBuildMetadataEntries = true,
                encryptSelectedConfigAssets = true,
                embedIntegrityManifest = true,
                generateSourceR8Rules = true,
                enableAggressiveRepackagingInSource = true,
            ),
        ),
        ProtectionProfile(
            id = "max_compatible_shield",
            name = "Maximum Compatible Shield",
            description = "Zero-breakage hardening preserving all manifest/reflection/JNI paths and keeping allowBackup intact.",
            enabledModules = setOf(
                ProtectionModuleId.STRING_FORGE,
                ProtectionModuleId.MANIFEST_FORGE,
                ProtectionModuleId.DEX_FORGE,
                ProtectionModuleId.INTEGRITY_FORGE,
                ProtectionModuleId.BUILD_GUARD,
            ),
            options = ProtectionEngineOptions(
                stripDexSourceFileMetadata = true,
                sealSensitiveStringsToVault = true,
                hardenManifestDebuggable = true,
                hardenManifestAllowBackup = false,
                stripBuildMetadataEntries = false,
                encryptSelectedConfigAssets = false,
                embedIntegrityManifest = true,
                generateSourceR8Rules = true,
                enableAggressiveRepackagingInSource = false,
            ),
        ),
        ProtectionProfile(
            id = "dex_focus_shield",
            name = "DEX Focus Shield",
            description = "Prioritizes multidex structural audit, source-file stripping, and R8 obfuscation configuration.",
            enabledModules = setOf(
                ProtectionModuleId.DEX_FORGE,
                ProtectionModuleId.INTEGRITY_FORGE,
                ProtectionModuleId.BUILD_GUARD,
            ),
            options = ProtectionEngineOptions(
                stripDexSourceFileMetadata = true,
                sealSensitiveStringsToVault = false,
                hardenManifestDebuggable = false,
                stripBuildMetadataEntries = false,
                encryptSelectedConfigAssets = false,
                embedIntegrityManifest = true,
                generateSourceR8Rules = true,
                enableAggressiveRepackagingInSource = true,
            ),
        ),
        ProtectionProfile(
            id = "string_focus_shield",
            name = "String Focus Shield",
            description = "Focuses on DEX string inventory classification, sensitive credential vaulting, and ConfigForge.",
            enabledModules = setOf(
                ProtectionModuleId.STRING_FORGE,
                ProtectionModuleId.CONFIG_FORGE,
                ProtectionModuleId.INTEGRITY_FORGE,
                ProtectionModuleId.BUILD_GUARD,
            ),
        ),
        ProtectionProfile(
            id = "resource_focus_shield",
            name = "Resource Focus Shield",
            description = "Targets ARSC analysis, build-metadata stripping, asset encryption, and 4-byte alignment.",
            enabledModules = setOf(
                ProtectionModuleId.RESOURCE_FORGE,
                ProtectionModuleId.CONFIG_FORGE,
                ProtectionModuleId.INTEGRITY_FORGE,
                ProtectionModuleId.BUILD_GUARD,
            ),
        ),
        ProtectionProfile(
            id = "manifest_focus_shield",
            name = "Manifest Focus Shield",
            description = "Enforces binary AXML attribute hardening, exported component review, and manifest integrity sealing.",
            enabledModules = setOf(
                ProtectionModuleId.MANIFEST_FORGE,
                ProtectionModuleId.INTEGRITY_FORGE,
                ProtectionModuleId.BUILD_GUARD,
            ),
        ),
        ProtectionProfile(
            id = "custom_forge",
            name = "Custom Forge",
            description = "Fully customizable per-engine, per-DEX, and per-component protection configuration.",
            enabledModules = setOf(
                ProtectionModuleId.STRING_FORGE,
                ProtectionModuleId.MANIFEST_FORGE,
                ProtectionModuleId.RESOURCE_FORGE,
                ProtectionModuleId.DEX_FORGE,
                ProtectionModuleId.INTEGRITY_FORGE,
                ProtectionModuleId.CONFIG_FORGE,
                ProtectionModuleId.BUILD_GUARD,
            ),
            isBuiltIn = false,
        ),
    )

    fun exportProfileJson(profile: ProtectionProfile): String = json.encodeToString(profile)

    fun importProfileJson(raw: String): ProtectionProfile =
        json.decodeFromString<ProtectionProfile>(raw).copy(isBuiltIn = false)
}
