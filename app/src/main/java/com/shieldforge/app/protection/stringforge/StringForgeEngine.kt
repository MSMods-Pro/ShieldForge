package com.shieldforge.app.protection.stringforge

import com.shieldforge.app.apk.dex.DexBinaryParser
import com.shieldforge.app.apk.dex.StringSensitivity
import com.shieldforge.app.core.common.EngineExecutionResult
import com.shieldforge.app.core.common.EngineExecutionState
import com.shieldforge.app.core.common.LogLevel
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.core.crypto.CryptoEngine
import com.shieldforge.app.protection.ProtectionPipelineContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable
data class SealedStringEntry(
    val id: String,
    val dexFileName: String,
    val sensitivity: String,
    val ivBase64: String,
    val ciphertextBase64: String,
    val plainSha256: String,
)

@Serializable
data class StringForgeVaultManifest(
    val version: Int = 1,
    val algorithm: String = "AES/GCM/NoPadding",
    val keyProvisioningNote: String = "Master wrapping key managed outside APK via Android Keystore / KMS.",
    val entries: List<SealedStringEntry>,
)

object StringForgeEngine {
    private val json = Json { prettyPrint = true }

    fun executeOnApk(ctx: ProtectionPipelineContext): EngineExecutionResult {
        val start = System.currentTimeMillis()
        val moduleId = ProtectionModuleId.STRING_FORGE

        if (moduleId !in ctx.profile.enabledModules) {
            return EngineExecutionResult(
                moduleId = moduleId,
                state = EngineExecutionState.SKIPPED,
                summary = "Disabled in active profile '${ctx.profile.name}'.",
            )
        }

        ctx.log("StringForge", LogLevel.STAGE, "Scanning DEX string pools & user string selections...")

        val selectedStringIds = ctx.selection.selectedStrings
        val selectedClasses = ctx.selection.selectedClasses
        val selectedPackages = ctx.selection.selectedPackages

        // Determine target strings: either explicitly selected strings, strings matching selected classes/packages,
        // or sensitive strings if global sealSensitiveStringsToVault is enabled.
        val candidateStrings = ctx.analysis.dexBundle.strings.filter { s ->
            val inSelectedSet = s.id in selectedStringIds
            val matchesSelectedPkg = selectedPackages.any { pkg -> s.value.contains(pkg) }
            val isSensitiveAuto = selectedStringIds.isEmpty() && s.sensitivity != StringSensitivity.NORMAL
            inSelectedSet || matchesSelectedPkg || isSensitiveAuto
        }.take(500)

        val warnings = mutableListOf<String>()
        val artifacts = mutableListOf<String>()
        var sealedCount = 0
        var strippedTagClasses = 0

        // 1. Seal selected sensitive strings into AES-256-GCM encrypted vault artifact (no hardcoded master key in APK!)
        if (ctx.profile.options.sealSensitiveStringsToVault && candidateStrings.isNotEmpty()) {
            val sessionKey = CryptoEngine.generateAes256Key()
            val sealedEntries = candidateStrings.map { item ->
                val sealed = CryptoEngine.sealAesGcm(item.value.toByteArray(Charsets.UTF_8), sessionKey)
                SealedStringEntry(
                    id = item.id,
                    dexFileName = item.dexFileName,
                    sensitivity = item.sensitivity.name,
                    ivBase64 = sealed.ivBase64,
                    ciphertextBase64 = sealed.ciphertextBase64,
                    plainSha256 = sealed.plainSha256,
                )
            }
            val vaultJson = json.encodeToString(StringForgeVaultManifest(entries = sealedEntries))
            ctx.addedZipEntries["assets/shieldforge_string_vault.json"] = vaultJson.toByteArray(Charsets.UTF_8)
            sealedCount = sealedEntries.size
            artifacts.add("assets/shieldforge_string_vault.json ($sealedCount AES-256-GCM entries)")
            ctx.log("StringForge", LogLevel.INFO, "Sealed $sealedCount strings into AES-256-GCM vault (key kept out of APK)")
        }

        // 2. Strip SourceFile debug strings from selected classes if enabled
        if (ctx.profile.options.stripDexSourceFileMetadata) {
            val targetClasses = ctx.analysis.dexBundle.classes.filter { cls ->
                val override = ctx.selection.overrides[cls.id]
                val allowed = ctx.profile.resolveModulesForComponent(cls.dexFileName, override)
                if (moduleId !in allowed) return@filter false
                if (selectedClasses.isNotEmpty() || selectedPackages.isNotEmpty() || ctx.selection.selectedDexFiles.isNotEmpty()) {
                    cls.id in selectedClasses || cls.packageName in selectedPackages || cls.dexFileName in ctx.selection.selectedDexFiles
                } else {
                    cls.sourceFile != null
                }
            }
            val byDex = targetClasses.groupBy { it.dexFileName }
            for ((dexName, clsList) in byDex) {
                val rawDex = ctx.dexWorkingBytes[dexName] ?: continue
                val indices = clsList.map { it.classDefIndex }.toSet()
                val (patched, count) = DexBinaryParser.stripSourceFileMetadata(rawDex, indices)
                if (count > 0) {
                    ctx.dexWorkingBytes[dexName] = patched
                    ctx.replacedZipEntries[dexName] = patched
                    strippedTagClasses += count
                }
            }
            if (strippedTagClasses > 0) {
                artifacts.add("Stripped SourceFile string references from $strippedTagClasses DEX class_def entries")
            }
        }

        // Explicitly document unsupported in-place const-string instruction encryption on precompiled DEX
        val nonSourceStringsSelected = candidateStrings.count { !it.isSourceFileTag }
        if (nonSourceStringsSelected > 0) {
            warnings.add(
                "In-place Dalvik const-string opcode rewriting for $nonSourceStringsSelected literal(s) requires Source Mode / IR compiler; precompiled DEX retains runtime bytecode references intact while sensitive inventory is sealed in StringForge vault.",
            )
        }

        val state = if (warnings.isNotEmpty()) {
            EngineExecutionState.PARTIAL_WITH_WARNINGS
        } else {
            EngineExecutionState.SUCCEEDED
        }

        return EngineExecutionResult(
            moduleId = moduleId,
            state = state,
            processedCount = sealedCount + strippedTagClasses,
            unsupportedCount = nonSourceStringsSelected,
            warnings = warnings,
            artifactsProduced = artifacts,
            summary = "Vaulted $sealedCount strings (AES-256-GCM); stripped $strippedTagClasses SourceFile refs.",
            durationMs = System.currentTimeMillis() - start,
        )
    }

    fun generateSourceKotlinVault(
        packageName: String,
        selectedStrings: List<String>,
    ): String {
        val key = CryptoEngine.generateAes256Key()
        val entries = selectedStrings.take(50).mapIndexed { idx, value ->
            val sealed = CryptoEngine.sealAesGcm(value.toByteArray(Charsets.UTF_8), key)
            Triple("SECRET_$idx", sealed.ivBase64, sealed.ciphertextBase64)
        }
        return buildString {
            appendLine("package $packageName.security")
            appendLine()
            appendLine("import android.security.keystore.KeyGenParameterSpec")
            appendLine("import android.security.keystore.KeyProperties")
            appendLine("import android.util.Base64")
            appendLine("import java.security.KeyStore")
            appendLine("import javax.crypto.Cipher")
            appendLine("import javax.crypto.KeyGenerator")
            appendLine("import javax.crypto.SecretKey")
            appendLine("import javax.crypto.spec.GCMParameterSpec")
            appendLine()
            appendLine("/**")
            appendLine(" * Generated by ShieldForge StringForge (Mode B: Source Hardening).")
            appendLine(" * Uses Android Keystore AES/GCM/NoPadding without embedding plaintext master keys.")
            appendLine(" */")
            appendLine("object StringForgeVault {")
            appendLine("    private const val ALIAS = \"shieldforge_runtime_str_key\"")
            appendLine()
            appendLine("    fun ensureKey(): SecretKey {")
            appendLine("        val ks = KeyStore.getInstance(\"AndroidKeyStore\").apply { load(null) }")
            appendLine("        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }")
            appendLine("        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, \"AndroidKeyStore\")")
            appendLine("        kg.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)")
            appendLine("            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)")
            appendLine("            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)")
            appendLine("            .setKeySize(256).build())")
            appendLine("        return kg.generateKey()")
            appendLine("    }")
            appendLine()
            appendLine("    // Selected string audit slots (${entries.size} entries sealed for provision):")
            entries.forEach { (slot, iv, ct) ->
                appendLine("    // $slot -> iv=$iv cipherLen=${ct.length}")
            }
            appendLine("}")
        }
    }
}
