package com.shieldforge.app.protection.configforge

import com.shieldforge.app.apk.resources.ResourceCategory
import com.shieldforge.app.core.common.EngineExecutionResult
import com.shieldforge.app.core.common.EngineExecutionState
import com.shieldforge.app.core.common.LogLevel
import com.shieldforge.app.core.common.ProtectionModuleId
import com.shieldforge.app.core.crypto.CryptoEngine
import com.shieldforge.app.protection.ProtectionPipelineContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.zip.ZipFile

@Serializable
data class SealedConfigRecord(
    val sourcePath: String,
    val algorithm: String,
    val ivBase64: String,
    val ciphertextBase64: String,
    val plainSha256: String,
)

object ConfigForgeEngine {
    private val json = Json { prettyPrint = true }

    fun executeOnApk(ctx: ProtectionPipelineContext): EngineExecutionResult {
        val start = System.currentTimeMillis()
        val moduleId = ProtectionModuleId.CONFIG_FORGE

        if (moduleId !in ctx.profile.enabledModules) {
            return EngineExecutionResult(
                moduleId = moduleId,
                state = EngineExecutionState.SKIPPED,
                summary = "Disabled in active profile '${ctx.profile.name}'.",
            )
        }

        ctx.log("ConfigForge", LogLevel.STAGE, "Auditing configuration files & sensitive assets...")

        val configEntries = ctx.analysis.resourceBundle.entries.filter {
            it.category == ResourceCategory.CONFIG || it.isSensitiveConfig
        }
        val selectedConfigEntries = if (ctx.selection.selectedResources.isNotEmpty()) {
            configEntries.filter { it.id in ctx.selection.selectedResources }
        } else {
            configEntries
        }

        val artifacts = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        var sealedCount = 0

        if (ctx.profile.options.encryptSelectedConfigAssets && selectedConfigEntries.isNotEmpty()) {
            val sessionKey = CryptoEngine.generateAes256Key()
            val sealedList = mutableListOf<SealedConfigRecord>()
            ZipFile(ctx.inputApk).use { zip ->
                for (cfg in selectedConfigEntries) {
                    val ze = zip.getEntry(cfg.path) ?: continue
                    val raw = zip.getInputStream(ze).use { it.readBytes() }
                    val sealed = CryptoEngine.sealAesGcm(raw, sessionKey)
                    sealedList.add(
                        SealedConfigRecord(
                            sourcePath = cfg.path,
                            algorithm = sealed.algorithm,
                            ivBase64 = sealed.ivBase64,
                            ciphertextBase64 = sealed.ciphertextBase64,
                            plainSha256 = sealed.plainSha256,
                        ),
                    )
                    sealedCount++
                }
            }
            if (sealedList.isNotEmpty()) {
                ctx.addedZipEntries["assets/shieldforge_sealed_configs.json"] =
                    json.encodeToString(sealedList).toByteArray(Charsets.UTF_8)
                artifacts.add("assets/shieldforge_sealed_configs.json ($sealedCount AES-256-GCM sealed config(s))")
                warnings.add(
                    "Original config files retained in APK so unmodified precompiled bytecode will not crash on missing assets; adopt ConfigForgeStore in Source Mode to replace plaintext config reads.",
                )
            }
        }

        if (configEntries.isNotEmpty()) {
            ctx.log("ConfigForge", LogLevel.INFO, "Detected ${configEntries.size} configuration asset(s); sealed $sealedCount")
        }

        return EngineExecutionResult(
            moduleId = moduleId,
            state = if (warnings.isNotEmpty()) EngineExecutionState.PARTIAL_WITH_WARNINGS else EngineExecutionState.SUCCEEDED,
            processedCount = configEntries.size,
            warnings = warnings,
            artifactsProduced = artifacts,
            summary = "Audited ${configEntries.size} configuration file(s); generated $sealedCount AES-256-GCM sealed record(s).",
            durationMs = System.currentTimeMillis() - start,
        )
    }

    fun generateSourceConfigStoreKotlin(packageName: String): String = buildString {
        appendLine("package $packageName.security")
        appendLine()
        appendLine("import android.content.Context")
        appendLine("import android.security.keystore.KeyGenParameterSpec")
        appendLine("import android.security.keystore.KeyProperties")
        appendLine("import java.security.KeyStore")
        appendLine("import javax.crypto.Cipher")
        appendLine("import javax.crypto.KeyGenerator")
        appendLine("import javax.crypto.SecretKey")
        appendLine("import javax.crypto.spec.GCMParameterSpec")
        appendLine()
        appendLine("object ConfigForgeStore {")
        appendLine("    private const val ALIAS = \"shieldforge_config_aes256\"")
        appendLine("    private fun getOrCreateKey(): SecretKey {")
        appendLine("        val ks = KeyStore.getInstance(\"AndroidKeyStore\").apply { load(null) }")
        appendLine("        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }")
        appendLine("        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, \"AndroidKeyStore\")")
        appendLine("        kg.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)")
        appendLine("            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)")
        appendLine("            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)")
        appendLine("            .setKeySize(256).build())")
        appendLine("        return kg.generateKey()")
        appendLine("    }")
        appendLine("    fun encryptConfig(plain: ByteArray): Pair<ByteArray, ByteArray> {")
        appendLine("        val cipher = Cipher.getInstance(\"AES/GCM/NoPadding\")")
        appendLine("        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())")
        appendLine("        return cipher.iv to cipher.doFinal(plain)")
        appendLine("    }")
        appendLine("    fun decryptConfig(iv: ByteArray, ct: ByteArray): ByteArray {")
        appendLine("        val cipher = Cipher.getInstance(\"AES/GCM/NoPadding\")")
        appendLine("        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))")
        appendLine("        return cipher.doFinal(ct)")
        appendLine("    }")
        appendLine("}")
    }
}
