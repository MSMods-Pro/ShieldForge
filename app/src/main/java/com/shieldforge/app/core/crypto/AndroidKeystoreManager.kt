package com.shieldforge.app.core.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class KeystoreAliasInfo(
    val alias: String,
    val algorithm: String,
    val subjectDn: String,
    val sha256Fingerprint: String,
    val sha1Fingerprint: String,
    val notAfterMs: Long,
    val isHardwareBackedOrKeystore: Boolean,
)

object AndroidKeystoreManager {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val MASTER_AES_ALIAS = "shieldforge_vault_master_aes"
    private const val DEFAULT_SIGNING_ALIAS = "shieldforge_apk_signer_rsa2048"

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun ensureMasterVaultKey(): SecretKey {
        val ks = loadKeyStore()
        val existing = ks.getKey(MASTER_AES_ALIAS, null) as? SecretKey
        if (existing != null) return existing

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            MASTER_AES_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    fun wrapSecret(plaintext: ByteArray): Pair<String, String> {
        val key = ensureMasterVaultKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encrypted = cipher.doFinal(plaintext)
        return Base64.encodeToString(cipher.iv, Base64.NO_WRAP) to
            Base64.encodeToString(encrypted, Base64.NO_WRAP)
    }

    fun unwrapSecret(ivBase64: String, cipherBase64: String): ByteArray {
        val key = ensureMasterVaultKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = Base64.decode(ivBase64, Base64.NO_WRAP)
        val encrypted = Base64.decode(cipherBase64, Base64.NO_WRAP)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(encrypted)
    }

    fun listKeystoreSigningAliases(): List<KeystoreAliasInfo> {
        return runCatching {
            val ks = loadKeyStore()
            val aliases = ks.aliases().toList()
            aliases.mapNotNull { alias ->
                if (!ks.isKeyEntry(alias) || alias == MASTER_AES_ALIAS) return@mapNotNull null
                val cert = ks.getCertificate(alias) as? X509Certificate ?: return@mapNotNull null
                val encoded = cert.encoded
                KeystoreAliasInfo(
                    alias = alias,
                    algorithm = cert.publicKey.algorithm,
                    subjectDn = cert.subjectX500Principal.name,
                    sha256Fingerprint = CryptoEngine.sha256Hex(encoded),
                    sha1Fingerprint = CryptoEngine.sha1Hex(encoded),
                    notAfterMs = cert.notAfter.time,
                    isHardwareBackedOrKeystore = true,
                )
            }
        }.getOrDefault(emptyList())
    }

    fun generateRsaSigningKeyInKeystore(
        alias: String = DEFAULT_SIGNING_ALIAS,
        commonName: String = "ShieldForge Studio Signer",
    ): KeystoreAliasInfo {
        val ks = loadKeyStore()
        if (!ks.containsAlias(alias)) {
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setCertificateSubject(javax.security.auth.x500.X500Principal("CN=$commonName, O=ShieldForge"))
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }
        val cert = ks.getCertificate(alias) as X509Certificate
        return KeystoreAliasInfo(
            alias = alias,
            algorithm = cert.publicKey.algorithm,
            subjectDn = cert.subjectX500Principal.name,
            sha256Fingerprint = CryptoEngine.sha256Hex(cert.encoded),
            sha1Fingerprint = CryptoEngine.sha1Hex(cert.encoded),
            notAfterMs = cert.notAfter.time,
            isHardwareBackedOrKeystore = true,
        )
    }

    fun getKeystorePrivateKeyAndCert(alias: String): Pair<PrivateKey, X509Certificate>? {
        return runCatching {
            val ks = loadKeyStore()
            val key = ks.getKey(alias, null) as? PrivateKey ?: return null
            val cert = ks.getCertificate(alias) as? X509Certificate ?: return null
            key to cert
        }.getOrNull()
    }
}
