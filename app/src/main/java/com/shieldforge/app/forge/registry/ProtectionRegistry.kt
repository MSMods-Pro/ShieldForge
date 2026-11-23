package com.shieldforge.app.forge.registry

import com.shieldforge.app.core.common.ProtectionModuleId

data class ProtectionEngineDescriptor(
    val moduleId: ProtectionModuleId,
    val modeACapabilities: List<String>,
    val modeALimitations: List<String>,
    val modeBCapabilities: List<String>,
    val preservesGuarantees: List<String>,
)

object ProtectionRegistry {
    val engines: List<ProtectionEngineDescriptor> = listOf(
        ProtectionEngineDescriptor(
            moduleId = ProtectionModuleId.STRING_FORGE,
            modeACapabilities = listOf(
                "Full MUTF-8 string pool extraction & sensitivity classification",
                "Strips leaking SourceFile debug strings from selected DEX class_defs",
                "Seals selected sensitive strings into AES-256-GCM asset vault",
            ),
            modeALimitations = listOf(
                "Arbitrary Dalvik const-string instruction rewriting requires Source Mode / IR recompilation (reported transparently)",
            ),
            modeBCapabilities = listOf(
                "Generates StringForgeVault.kt backed by Android Keystore AES/GCM/NoPadding",
                "Encrypts selected literal payloads without embedding raw master keys",
            ),
            preservesGuarantees = listOf("Runtime string semantics", "Class descriptors & JNI signatures"),
        ),
        ProtectionEngineDescriptor(
            moduleId = ProtectionModuleId.MANIFEST_FORGE,
            modeACapabilities = listOf(
                "Binary AXML parsing of components, permissions, SDK levels, and meta-data",
                "In-place hardening of existing android:debuggable and android:allowBackup flags",
                "Computes manifest SHA-256 integrity seal",
            ),
            modeALimitations = listOf(
                "Structural addition of new manifest nodes requires Source Mode",
            ),
            modeBCapabilities = listOf(
                "Generates hardened AndroidManifest.xml release merge rules & exported-component guards",
            ),
            preservesGuarantees = listOf("Activities", "Services", "Receivers", "Providers", "Intent filters", "SDK requirements"),
        ),
        ProtectionEngineDescriptor(
            moduleId = ProtectionModuleId.RESOURCE_FORGE,
            modeACapabilities = listOf(
                "Parses resources.arsc type/key pools and classifies all res/ & assets/ entries",
                "Strips safe compiler metadata (.kotlin_builtins, META-INF/*.version) when selected",
                "Encrypts selected raw assets with AES-256-GCM (.sfenc)",
            ),
            modeALimitations = listOf(
                "Resource ID obfuscation requires AAPT2 recompilation in Source Mode",
            ),
            modeBCapabilities = listOf(
                "Enables R8 resource shrinking (isShrinkResources = true) and resource keep-rules",
            ),
            preservesGuarantees = listOf("All ARSC resource IDs", "Native .so ABIs", "Launcher/UI drawables"),
        ),
        ProtectionEngineDescriptor(
            moduleId = ProtectionModuleId.DEX_FORGE,
            modeACapabilities = listOf(
                "Parses DEX 035–041 headers, classes, methods, fields & multidex links",
                "Per-DEX / per-package / per-class SourceFile metadata stripping + checksum rebuild",
                "Validates Adler-32, SHA-1, and table bounds after transformation",
            ),
            modeALimitations = listOf(
                "Identifier renaming & bytecode control-flow flattening require R8/Source Mode (never fakes unsafe DEX patching)",
            ),
            modeBCapabilities = listOf(
                "Generates tailored proguard-rules.pro with R8 full-mode & entry-point keep rules",
            ),
            preservesGuarantees = listOf("Application entry points", "Reflection targets", "JNI native methods", "Serialization"),
        ),
        ProtectionEngineDescriptor(
            moduleId = ProtectionModuleId.INTEGRITY_FORGE,
            modeACapabilities = listOf(
                "Computes SHA-256 digests for APK, every classes*.dex, Manifest, and resources.arsc",
                "Embeds signed shieldforge_integrity.json build fingerprint inside output APK",
            ),
            modeALimitations = listOf(
                "Runtime self-check hook injection into precompiled bytecode requires Source Mode",
            ),
            modeBCapabilities = listOf(
                "Generates IntegrityForgeGuard.kt (signing cert SHA-256 + debuggable + APK digest check)",
            ),
            preservesGuarantees = listOf("Deterministic verification digests"),
        ),
        ProtectionEngineDescriptor(
            moduleId = ProtectionModuleId.CONFIG_FORGE,
            modeACapabilities = listOf(
                "Audits assets/ and res/raw/ configuration files for exposed URLs/keys",
                "Encrypts selected app-owned config files via AES-256-GCM",
            ),
            modeALimitations = listOf(
                "Consumer app must integrate ConfigForgeStore reader to consume .sfenc assets",
            ),
            modeBCapabilities = listOf(
                "Generates ConfigForgeStore.kt using Android Keystore AES/GCM/NoPadding",
            ),
            preservesGuarantees = listOf("No plaintext master keys embedded in APK"),
        ),
        ProtectionEngineDescriptor(
            moduleId = ProtectionModuleId.BUILD_GUARD,
            modeACapabilities = listOf(
                "Preserves original input APK in isolated workspace",
                "Reconstructs ZIP with 4-byte alignment on STORED resources.arsc & .so libs",
                "Applies JAR v1 + APK Signature Scheme v2 and verifies final signatures",
            ),
            modeALimitations = listOf(
                "Re-signing alters signing identity; updates over installs signed by a different cert are blocked by Android",
            ),
            modeBCapabilities = listOf(
                "Produces release hardening bundle & Gradle signing config template",
            ),
            preservesGuarantees = listOf("Input APK untouched", "Valid ZIP & signature structure"),
        ),
    )

    fun descriptorFor(id: ProtectionModuleId): ProtectionEngineDescriptor =
        engines.first { it.moduleId == id }
}
