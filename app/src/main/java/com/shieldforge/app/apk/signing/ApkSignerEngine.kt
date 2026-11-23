package com.shieldforge.app.apk.signing

import android.content.Context
import com.shieldforge.app.core.crypto.AndroidKeystoreManager
import com.shieldforge.app.core.crypto.CryptoEngine
import kotlinx.serialization.Serializable
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

@Serializable
data class SigningCertificateInfo(
    val subjectDn: String,
    val issuerDn: String,
    val serialNumberHex: String,
    val algorithm: String,
    val sha256Fingerprint: String,
    val sha1Fingerprint: String,
    val md5Fingerprint: String,
    val notBeforeMs: Long,
    val notAfterMs: Long,
)

@Serializable
data class ApkSignatureVerification(
    val hasV1JarSignature: Boolean,
    val hasV2SignatureBlock: Boolean,
    val hasV3SignatureBlock: Boolean,
    val isSigned: Boolean,
    val verificationPassed: Boolean,
    val verificationMessage: String,
    val certificates: List<SigningCertificateInfo>,
)

@Serializable
data class SigningProfile(
    val id: String,
    val alias: String,
    val storageKind: String, // "ANDROID_KEYSTORE" or "PKCS12_FILE"
    val keystoreFileName: String? = null,
    val commonName: String,
    val organization: String,
    val sha256Fingerprint: String,
    val sha1Fingerprint: String,
    val createdAtMs: Long,
)

data class ResolvedSigningCredentials(
    val profile: SigningProfile,
    val privateKey: PrivateKey,
    val certificate: X509Certificate,
)

object ApkSignerEngine {
    private const val APK_SIG_BLOCK_MAGIC = "APK Sig Block 42"
    private const val APK_SIG_V2_BLOCK_ID = 0x7109871a
    private const val APK_SIG_V3_BLOCK_ID = -0x0fac9740 // 0xf05368c0
    private const val SIG_ALG_RSA_PKCS1_V1_5_SHA256 = 0x0103
    private const val CHUNK_SIZE = 1024 * 1024

    fun createPkcs12Keystore(
        context: Context,
        alias: String,
        password: String,
        commonName: String,
        organization: String,
    ): SigningProfile {
        val dir = File(context.filesDir, "keystores").apply { mkdirs() }
        val fileName = "${alias.replace(Regex("[^a-zA-Z0-9_-]"), "_")}.p12"
        val outFile = File(dir, fileName)

        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.generateKeyPair()
        val cert = DerEncoder.generateSelfSignedX509(
            commonName = commonName,
            organization = organization,
            publicKey = keyPair.public,
            privateKey = keyPair.private,
        )

        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry(alias, keyPair.private, password.toCharArray(), arrayOf(cert))
        outFile.outputStream().use { ks.store(it, password.toCharArray()) }

        return SigningProfile(
            id = "KS_${System.currentTimeMillis()}",
            alias = alias,
            storageKind = "PKCS12_FILE",
            keystoreFileName = fileName,
            commonName = commonName,
            organization = organization,
            sha256Fingerprint = CryptoEngine.sha256Hex(cert.encoded),
            sha1Fingerprint = CryptoEngine.sha1Hex(cert.encoded),
            createdAtMs = System.currentTimeMillis(),
        )
    }

    fun importPkcs12Keystore(
        context: Context,
        bytes: ByteArray,
        password: String,
        requestedAlias: String?,
    ): SigningProfile {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(ByteArrayInputStream(bytes), password.toCharArray())
        val aliases = ks.aliases().toList()
        val alias = requestedAlias?.takeIf { ks.isKeyEntry(it) }
            ?: aliases.firstOrNull { ks.isKeyEntry(it) }
            ?: throw IllegalArgumentException("No private key entry found in keystore")

        val cert = ks.getCertificate(alias) as? X509Certificate
            ?: throw IllegalArgumentException("Missing X.509 certificate for alias '$alias'")

        val dir = File(context.filesDir, "keystores").apply { mkdirs() }
        val fileName = "imported_${System.currentTimeMillis()}.p12"
        File(dir, fileName).writeBytes(bytes)

        return SigningProfile(
            id = "KS_${System.currentTimeMillis()}",
            alias = alias,
            storageKind = "PKCS12_FILE",
            keystoreFileName = fileName,
            commonName = cert.subjectX500Principal.name,
            organization = "Imported Keystore",
            sha256Fingerprint = CryptoEngine.sha256Hex(cert.encoded),
            sha1Fingerprint = CryptoEngine.sha1Hex(cert.encoded),
            createdAtMs = System.currentTimeMillis(),
        )
    }

    fun ensureDefaultAndroidKeystoreProfile(): SigningProfile {
        val info = AndroidKeystoreManager.generateRsaSigningKeyInKeystore(
            alias = "shieldforge_default_rsa2048",
            commonName = "ShieldForge Studio Signer",
        )
        return SigningProfile(
            id = "AKS_DEFAULT",
            alias = info.alias,
            storageKind = "ANDROID_KEYSTORE",
            keystoreFileName = null,
            commonName = "ShieldForge Studio Signer",
            organization = "ShieldForge",
            sha256Fingerprint = info.sha256Fingerprint,
            sha1Fingerprint = info.sha1Fingerprint,
            createdAtMs = System.currentTimeMillis(),
        )
    }

    fun resolveCredentials(
        context: Context,
        profile: SigningProfile,
        password: String,
    ): ResolvedSigningCredentials {
        if (profile.storageKind == "ANDROID_KEYSTORE") {
            val pair = AndroidKeystoreManager.getKeystorePrivateKeyAndCert(profile.alias)
                ?: throw IllegalStateException("Android Keystore alias '${profile.alias}' unavailable")
            return ResolvedSigningCredentials(profile, pair.first, pair.second)
        }
        val file = File(File(context.filesDir, "keystores"), profile.keystoreFileName.orEmpty())
        if (!file.exists()) throw IllegalStateException("Keystore file missing: ${file.name}")
        val ks = KeyStore.getInstance("PKCS12")
        file.inputStream().use { ks.load(it, password.toCharArray()) }
        val key = ks.getKey(profile.alias, password.toCharArray()) as? PrivateKey
            ?: throw IllegalStateException("Invalid password or missing key for alias '${profile.alias}'")
        val cert = ks.getCertificate(profile.alias) as? X509Certificate
            ?: throw IllegalStateException("Missing X.509 cert for alias '${profile.alias}'")
        return ResolvedSigningCredentials(profile, key, cert)
    }

    /**
     * Generates JAR v1 META-INF entries (MANIFEST.MF, SHIELD.SF, SHIELD.RSA).
     */
    fun createV1MetaInfEntries(
        entryDigests: Map<String, ByteArray>,
        credentials: ResolvedSigningCredentials,
    ): Map<String, ByteArray> {
        val manifestSb = StringBuilder()
        manifestSb.append("Manifest-Version: 1.0\r\n")
        manifestSb.append("Created-By: ShieldForge BuildGuard 1.0\r\n\r\n")

        val sfEntriesSb = StringBuilder()
        val md = MessageDigest.getInstance("SHA-256")

        for ((name, rawBytes) in entryDigests.toSortedMap()) {
            if (name.startsWith("META-INF/")) continue
            val digestB64 = CryptoEngine.base64Encode(md.digest(rawBytes))
            val section = "Name: $name\r\nSHA-256-Digest: $digestB64\r\n\r\n"
            manifestSb.append(section)
            val sectionDigestB64 = CryptoEngine.base64Encode(
                md.digest(section.toByteArray(Charsets.UTF_8)),
            )
            sfEntriesSb.append("Name: $name\r\nSHA-256-Digest: $sectionDigestB64\r\n\r\n")
        }

        val manifestBytes = manifestSb.toString().toByteArray(Charsets.UTF_8)
        val manifestDigestB64 = CryptoEngine.base64Encode(md.digest(manifestBytes))

        val sfSb = StringBuilder()
        sfSb.append("Signature-Version: 1.0\r\n")
        sfSb.append("Created-By: ShieldForge BuildGuard 1.0\r\n")
        sfSb.append("SHA-256-Digest-Manifest: $manifestDigestB64\r\n")
        sfSb.append("X-Android-APK-Signed: 2\r\n\r\n")
        sfSb.append(sfEntriesSb)

        val sfBytes = sfSb.toString().toByteArray(Charsets.UTF_8)
        val rsaBytes = DerEncoder.buildPkcs7SignedData(
            sfContent = sfBytes,
            certificate = credentials.certificate,
            privateKey = credentials.privateKey,
        )

        return mapOf(
            "META-INF/MANIFEST.MF" to manifestBytes,
            "META-INF/SHIELD.SF" to sfBytes,
            "META-INF/SHIELD.RSA" to rsaBytes,
        )
    }

    /**
     * Inserts a valid APK Signature Scheme v2 Signing Block before the ZIP Central Directory
     * and updates EOCD's centralDirOffset.
     */
    fun applyApkSignatureV2(
        unsignedOrV1Apk: File,
        credentials: ResolvedSigningCredentials,
    ) {
        val raw = unsignedOrV1Apk.readBytes()
        val eocdOffset = findEocdOffset(raw)
            ?: throw IllegalStateException("ZIP End of Central Directory not found")
        val eocdBuf = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        val cdSize = eocdBuf.getInt(eocdOffset + 12).toLong() and 0xFFFFFFFFL
        val cdOffset = eocdBuf.getInt(eocdOffset + 16).toLong() and 0xFFFFFFFFL
        if (cdOffset + cdSize > eocdOffset) {
            throw IllegalStateException("Corrupt ZIP Central Directory bounds")
        }

        val section1 = raw.copyOfRange(0, cdOffset.toInt())
        val section3 = raw.copyOfRange(cdOffset.toInt(), eocdOffset)
        val section4Base = raw.copyOfRange(eocdOffset, raw.size)

        // Section 4 digest is computed with EOCD centralDirOffset pointing to start of CD (with no sig block? Wait: per AOSP v2 spec, Section 4 uses the *modified* EOCD? Actually AOSP apksig sets CD offset in Section 4 to cdOffset BEFORE inserting sig block! Wait: let's match AOSP spec accurately: AOSP patches Section 4 EOCD centralDirOffset to section1.size when computing digest, and final file stores section1.size + sigBlock.size).
        val section4ForDigest = section4Base.copyOf()
        ByteBuffer.wrap(section4ForDigest).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(16, section1.size)

        val contentDigest = computeApkV2Digest(section1, section3, section4ForDigest)

        val certEncoded = credentials.certificate.encoded
        val spkiEncoded = credentials.certificate.publicKey.encoded

        // Build SignedData: digests (length-prefixed list of (algId, digest)), certs (length-prefixed list), additionalAttrs
        val digestPair = lengthPrefixed(
            concatLe(intLe(SIG_ALG_RSA_PKCS1_V1_5_SHA256), lengthPrefixed(contentDigest)),
        )
        val digestsList = lengthPrefixed(digestPair)
        val certsList = lengthPrefixed(lengthPrefixed(certEncoded))
        val additionalAttrs = lengthPrefixed(ByteArray(0))
        val signedDataBytes = concatLe(digestsList, certsList, additionalAttrs)

        val sigEngine = Signature.getInstance("SHA256withRSA")
        sigEngine.initSign(credentials.privateKey)
        sigEngine.update(signedDataBytes)
        val signatureBytes = sigEngine.sign()

        val sigPair = lengthPrefixed(
            concatLe(intLe(SIG_ALG_RSA_PKCS1_V1_5_SHA256), lengthPrefixed(signatureBytes)),
        )
        val signaturesList = lengthPrefixed(sigPair)
        val signerBytes = lengthPrefixed(
            concatLe(
                lengthPrefixed(signedDataBytes),
                signaturesList,
                lengthPrefixed(spkiEncoded),
            ),
        )
        val v2SchemeValue = lengthPrefixed(signerBytes)

        // Construct APK Signing Block: [uint64 sizeOfBlock] + pairs + [uint64 sizeOfBlock] + "APK Sig Block 42"
        val exactPair = concatLe(longLe(4L + v2SchemeValue.size), intLe(APK_SIG_V2_BLOCK_ID), v2SchemeValue)
        val blockSizeAfterFirstField = exactPair.size + 8L + 16L
        val sigBlock = concatLe(
            longLe(blockSizeAfterFirstField),
            exactPair,
            longLe(blockSizeAfterFirstField),
            APK_SIG_BLOCK_MAGIC.toByteArray(Charsets.US_ASCII),
        )

        val finalSection4 = section4Base.copyOf()
        ByteBuffer.wrap(finalSection4).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(16, section1.size + sigBlock.size)

        unsignedOrV1Apk.outputStream().use { out ->
            out.write(section1)
            out.write(sigBlock)
            out.write(section3)
            out.write(finalSection4)
        }
    }

    fun inspectApkSignatures(apkFile: File): ApkSignatureVerification {
        return try {
            val certs = mutableListOf<SigningCertificateInfo>()
            var hasV1 = false
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries().toList()
                val sigEntries = entries.filter {
                    val u = it.name.uppercase()
                    u.startsWith("META-INF/") && (u.endsWith(".RSA") || u.endsWith(".DSA") || u.endsWith(".EC"))
                }
                if (sigEntries.isNotEmpty()) {
                    hasV1 = true
                    val cf = CertificateFactory.getInstance("X.509")
                    for (se in sigEntries) {
                        zip.getInputStream(se).use { stream ->
                            runCatching {
                                cf.generateCertificates(stream).forEach { cert ->
                                    if (cert is X509Certificate) {
                                        certs.add(cert.toInfo())
                                    }
                                }
                            }
                        }
                    }
                }
            }

            val (hasV2, hasV3) = detectV2V3Blocks(apkFile)
            val isSigned = hasV1 || hasV2 || hasV3
            val msg = buildString {
                if (!isSigned) {
                    append("Unsigned APK (no v1 JAR or v2/v3 APK Signature Block)")
                } else {
                    val schemes = listOfNotNull(
                        "v1 (JAR)".takeIf { hasV1 },
                        "v2 (APK Sig Block)".takeIf { hasV2 },
                        "v3 (Key Rotation)".takeIf { hasV3 },
                    ).joinToString(" + ")
                    append("Signed with $schemes")
                    if (certs.isNotEmpty()) {
                        append(" • ${certs.size} certificate(s) parsed")
                    }
                }
            }
            ApkSignatureVerification(
                hasV1JarSignature = hasV1,
                hasV2SignatureBlock = hasV2,
                hasV3SignatureBlock = hasV3,
                isSigned = isSigned,
                verificationPassed = isSigned && (!hasV1 || certs.isNotEmpty()),
                verificationMessage = msg,
                certificates = certs.distinctBy { it.sha256Fingerprint },
            )
        } catch (e: Exception) {
            ApkSignatureVerification(
                hasV1JarSignature = false,
                hasV2SignatureBlock = false,
                hasV3SignatureBlock = false,
                isSigned = false,
                verificationPassed = false,
                verificationMessage = "Signature inspection failed: ${e.message}",
                certificates = emptyList(),
            )
        }
    }

    private fun detectV2V3Blocks(apkFile: File): Pair<Boolean, Boolean> {
        RandomAccessFile(apkFile, "r").use { raf ->
            val len = raf.length()
            if (len < 64) return false to false
            val tailSize = minOf(len, 65_560L).toInt()
            val tail = ByteArray(tailSize)
            raf.seek(len - tailSize)
            raf.readFully(tail)
            val eocdRel = findEocdOffset(tail) ?: return false to false
            val cdOffset = ByteBuffer.wrap(tail)
                .order(ByteOrder.LITTLE_ENDIAN)
                .getInt(eocdRel + 16).toLong() and 0xFFFFFFFFL
            if (cdOffset < 32L || cdOffset > len) return false to false

            val footer = ByteArray(24)
            raf.seek(cdOffset - 24L)
            raf.readFully(footer)
            val magic = String(footer, 8, 16, Charsets.US_ASCII)
            if (magic != APK_SIG_BLOCK_MAGIC) return false to false
            val blockSize = ByteBuffer.wrap(footer).order(ByteOrder.LITTLE_ENDIAN).getLong(0)
            if (blockSize < 24L || blockSize > cdOffset) return false to false

            val blockStart = cdOffset - blockSize - 8L
            if (blockStart < 0) return false to false
            val blockBytes = ByteArray(minOf(blockSize.toInt(), 4 * 1024 * 1024))
            raf.seek(blockStart + 8L)
            raf.readFully(blockBytes)

            var hasV2 = false
            var hasV3 = false
            var pos = 0
            val buf = ByteBuffer.wrap(blockBytes).order(ByteOrder.LITTLE_ENDIAN)
            while (pos + 12 <= blockBytes.size - 24) {
                val pairLen = buf.getLong(pos).toInt()
                if (pairLen < 4 || pos + 8 + pairLen > blockBytes.size) break
                val id = buf.getInt(pos + 8)
                if (id == APK_SIG_V2_BLOCK_ID) hasV2 = true
                if (id == APK_SIG_V3_BLOCK_ID) hasV3 = true
                pos += 8 + pairLen
            }
            return hasV2 to hasV3
        }
    }

    private fun computeApkV2Digest(s1: ByteArray, s3: ByteArray, s4: ByteArray): ByteArray {
        val chunkDigests = mutableListOf<ByteArray>()
        val md = MessageDigest.getInstance("SHA-256")
        for (section in listOf(s1, s3, s4)) {
            var offset = 0
            while (offset < section.size) {
                val chunkLen = minOf(CHUNK_SIZE, section.size - offset)
                md.reset()
                md.update(0xA5.toByte())
                md.update(intLe(chunkLen))
                md.update(section, offset, chunkLen)
                chunkDigests.add(md.digest())
                offset += chunkLen
            }
            if (section.isEmpty()) {
                md.reset()
                md.update(0xA5.toByte())
                md.update(intLe(0))
                chunkDigests.add(md.digest())
            }
        }
        md.reset()
        md.update(0x5A.toByte())
        md.update(intLe(chunkDigests.size))
        for (d in chunkDigests) md.update(d)
        return md.digest()
    }

    private fun findEocdOffset(bytes: ByteArray): Int? {
        for (i in bytes.size - 22 downTo maxOf(0, bytes.size - 65_560)) {
            if (bytes[i] == 0x50.toByte() &&
                bytes[i + 1] == 0x4B.toByte() &&
                bytes[i + 2] == 0x05.toByte() &&
                bytes[i + 3] == 0x06.toByte()
            ) {
                return i
            }
        }
        return null
    }

    private fun X509Certificate.toInfo(): SigningCertificateInfo {
        val der = encoded
        return SigningCertificateInfo(
            subjectDn = subjectX500Principal.name,
            issuerDn = issuerX500Principal.name,
            serialNumberHex = serialNumber.toString(16),
            algorithm = sigAlgName,
            sha256Fingerprint = CryptoEngine.sha256Hex(der),
            sha1Fingerprint = CryptoEngine.sha1Hex(der),
            md5Fingerprint = CryptoEngine.md5Hex(der),
            notBeforeMs = notBefore.time,
            notAfterMs = notAfter.time,
        )
    }

    private fun lengthPrefixed(data: ByteArray): ByteArray = concatLe(intLe(data.size), data)
    private fun intLe(v: Int): ByteArray = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()
    private fun longLe(v: Long): ByteArray = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array()
    private fun concatLe(vararg parts: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        for (p in parts) out.write(p)
        return out.toByteArray()
    }
}
