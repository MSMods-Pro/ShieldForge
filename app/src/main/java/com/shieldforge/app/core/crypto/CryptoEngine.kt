package com.shieldforge.app.core.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.Adler32
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class SealedPayload(
    val algorithm: String,
    val ivBase64: String,
    val ciphertextBase64: String,
    val plainSha256: String,
)

object CryptoEngine {
    private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12
    private val secureRandom = SecureRandom()
    private const val B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun base64Encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val sb = StringBuilder(((data.size + 2) / 3) * 4)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xFF
            val hasB1 = i + 1 < data.size
            val hasB2 = i + 2 < data.size
            val b1 = if (hasB1) data[i + 1].toInt() and 0xFF else 0
            val b2 = if (hasB2) data[i + 2].toInt() and 0xFF else 0
            sb.append(B64_CHARS[(b0 ushr 2) and 0x3F])
            sb.append(B64_CHARS[((b0 and 0x03) shl 4) or ((b1 ushr 4) and 0x0F)])
            sb.append(if (hasB1) B64_CHARS[((b1 and 0x0F) shl 2) or ((b2 ushr 6) and 0x03)] else '=')
            sb.append(if (hasB2) B64_CHARS[b2 and 0x3F] else '=')
            i += 3
        }
        return sb.toString()
    }

    fun base64Decode(input: String): ByteArray {
        val clean = input.filter { !it.isWhitespace() }
        if (clean.isEmpty()) return ByteArray(0)
        val out = ArrayList<Byte>((clean.length * 3) / 4)
        var i = 0
        while (i + 3 < clean.length) {
            val c0 = B64_CHARS.indexOf(clean[i])
            val c1 = B64_CHARS.indexOf(clean[i + 1])
            val c2 = if (clean[i + 2] == '=') -1 else B64_CHARS.indexOf(clean[i + 2])
            val c3 = if (clean[i + 3] == '=') -1 else B64_CHARS.indexOf(clean[i + 3])
            out.add(((c0 shl 2) or (c1 ushr 4)).toByte())
            if (c2 >= 0) out.add((((c1 and 0x0F) shl 4) or (c2 ushr 2)).toByte())
            if (c3 >= 0) out.add((((c2 and 0x03) shl 6) or c3).toByte())
            i += 4
        }
        return out.toByteArray()
    }

    fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun sha1Bytes(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-1").digest(bytes)

    fun sha1Hex(bytes: ByteArray): String =
        sha1Bytes(bytes).joinToString("") { "%02x".format(it) }

    fun md5Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("MD5").digest(bytes).joinToString("") { "%02x".format(it) }

    fun adler32(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): Long {
        val adler = Adler32()
        adler.update(bytes, offset, length)
        return adler.value
    }

    fun generateAes256Key(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256, secureRandom)
        return generator.generateKey()
    }

    fun secretKeyFromBytes(raw: ByteArray): SecretKey =
        SecretKeySpec(raw, "AES")

    fun sealAesGcm(plaintext: ByteArray, secretKey: SecretKey): SealedPayload {
        val iv = ByteArray(GCM_IV_BYTES)
        secureRandom.nextBytes(iv)
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        val ciphertext = cipher.doFinal(plaintext)
        return SealedPayload(
            algorithm = AES_GCM_TRANSFORMATION,
            ivBase64 = base64Encode(iv),
            ciphertextBase64 = base64Encode(ciphertext),
            plainSha256 = sha256Hex(plaintext),
        )
    }

    fun openAesGcm(payload: SealedPayload, secretKey: SecretKey): ByteArray {
        val iv = base64Decode(payload.ivBase64)
        val ciphertext = base64Decode(payload.ciphertextBase64)
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    fun randomBytes(count: Int): ByteArray = ByteArray(count).also { secureRandom.nextBytes(it) }
}
