package com.shieldforge.app

import com.shieldforge.app.apk.builder.ApkBuilderEngine
import com.shieldforge.app.apk.dex.DexBinaryParser
import com.shieldforge.app.apk.manifest.BinaryManifestParser
import com.shieldforge.app.apk.parser.ApkArchiveParser
import com.shieldforge.app.apk.signing.ApkSignerEngine
import com.shieldforge.app.apk.signing.DerEncoder
import com.shieldforge.app.apk.signing.ResolvedSigningCredentials
import com.shieldforge.app.apk.signing.SigningProfile
import com.shieldforge.app.core.crypto.CryptoEngine
import com.shieldforge.app.forge.profiles.ProtectionProfilesCatalog
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ShieldForgeEngineTest {

    @Test
    fun `aes gcm seal and open roundtrip`() {
        val key = CryptoEngine.generateAes256Key()
        val secret = "https://api.shieldforge.internal/v1/token".toByteArray()
        val sealed = CryptoEngine.sealAesGcm(secret, key)
        val opened = CryptoEngine.openAesGcm(sealed, key)
        assertArrayEquals(secret, opened)
    }

    @Test
    fun `dex binary parser parses classes strings and strips sourceFile safely`() {
        val dexBytes = buildMinimalValidDex(
            classDescriptor = "Lcom/demo/AuthService;",
            sourceFileName = "AuthService.kt",
        )
        val parsed = DexBinaryParser.parseSingleDex("classes.dex", dexBytes)
        assertTrue(parsed.summary.isSupportedVersion)
        assertTrue(parsed.summary.adler32Valid)
        assertTrue(parsed.summary.sha1Valid)
        assertEquals(1, parsed.classes.size)
        assertEquals("com.demo.AuthService", parsed.classes.first().className)
        assertEquals("AuthService.kt", parsed.classes.first().sourceFile)

        val (stripped, modified) = DexBinaryParser.stripSourceFileMetadata(dexBytes, setOf(0))
        assertEquals(1, modified)
        val (validAfter, _) = DexBinaryParser.validateDexBytes(stripped)
        assertTrue(validAfter)
        val reparsed = DexBinaryParser.parseSingleDex("classes.dex", stripped)
        assertEquals(null, reparsed.classes.first().sourceFile)
    }

    @Test
    fun `buildguard rebuilds aligns and dual-signs apk with v1 and v2 signatures`() {
        val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val kp = kpg.generateKeyPair()
        val cert = DerEncoder.generateSelfSignedX509("ShieldForge QA", "ShieldForge", kp.public, kp.private)
        val profile = SigningProfile(
            id = "test",
            alias = "qa_key",
            storageKind = "PKCS12_FILE",
            commonName = "ShieldForge QA",
            organization = "ShieldForge",
            sha256Fingerprint = CryptoEngine.sha256Hex(cert.encoded),
            sha1Fingerprint = CryptoEngine.sha1Hex(cert.encoded),
            createdAtMs = System.currentTimeMillis(),
        )
        val creds = ResolvedSigningCredentials(profile, kp.private, cert)

        val tempDir = Files.createTempDirectory("sf_test").toFile()
        val inApk = File(tempDir, "in.apk")
        val outApk = File(tempDir, "out.apk")

        val dexBytes = buildMinimalValidDex("Lcom/demo/MainActivity;", "MainActivity.kt")
        ZipOutputStream(FileOutputStream(inApk)).use { zos ->
            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(dexBytes)
            zos.closeEntry()
            zos.putNextEntry(ZipEntry("assets/config.json"))
            zos.write("""{"endpoint":"https://example.org"}""".toByteArray())
            zos.closeEntry()
        }

        ApkBuilderEngine.rebuildAndSignApk(
            inputApk = inApk,
            outputApk = outApk,
            replacedEntries = emptyMap(),
            addedEntries = mapOf("assets/shieldforge_integrity.json" to "{}".toByteArray()),
            removedEntries = emptySet(),
            credentials = creds,
        )

        val sigCheck = ApkSignerEngine.inspectApkSignatures(outApk)
        assertTrue(sigCheck.hasV1JarSignature)
        assertTrue(sigCheck.hasV2SignatureBlock)
        assertTrue(sigCheck.verificationPassed)

        val analysis = ApkArchiveParser.analyzeApk("TEST", outApk.name, outApk)
        assertEquals(1, analysis.dexBundle.dexFiles.size)
        assertTrue(analysis.dexBundle.dexFiles.first().adler32Valid)
        assertTrue(analysis.dexBundle.dexFiles.first().sha1Valid)
        tempDir.deleteRecursively()
    }

    @Test
    fun `all 9 protection profiles export and import cleanly`() {
        assertEquals(9, ProtectionProfilesCatalog.builtInProfiles.size)
        val pro = ProtectionProfilesCatalog.builtInProfiles.first { it.id == "professional_shield" }
        val json = ProtectionProfilesCatalog.exportProfileJson(pro)
        val reimported = ProtectionProfilesCatalog.importProfileJson(json)
        assertEquals(pro.name, reimported.name)
        assertEquals(pro.enabledModules, reimported.enabledModules)
        assertFalse(reimported.isBuiltIn)
    }

    @Test
    fun `invalid axml bytes safely return invalid result without crashing`() {
        val res = BinaryManifestParser.parse(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9))
        assertFalse(res.isValidAxml)
    }

    private fun buildMinimalValidDex(
        classDescriptor: String,
        sourceFileName: String,
    ): ByteArray {
        val strings = listOf(classDescriptor, "Ljava/lang/Object;", sourceFileName)
        val dataOut = ByteArrayOutputStream()
        val stringDataBaseOffset = 112 + (strings.size * 4) + (2 * 4) + 32
        val strOffsets = IntArray(strings.size)
        for (i in strings.indices) {
            strOffsets[i] = stringDataBaseOffset + dataOut.size()
            val utf8 = strings[i].toByteArray(Charsets.UTF_8)
            dataOut.write(utf8.size)
            dataOut.write(utf8)
            dataOut.write(0)
        }
        val strDataBytes = dataOut.toByteArray()
        val totalSize = stringDataBaseOffset + strDataBytes.size
        val dex = ByteArray(totalSize)
        val buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)

        System.arraycopy("dex\n039\u0000".toByteArray(Charsets.US_ASCII), 0, dex, 0, 8)
        buf.putInt(32, totalSize)
        buf.putInt(36, 0x70)
        buf.putInt(40, 0x12345678)
        buf.putInt(56, strings.size)
        buf.putInt(60, 112)
        buf.putInt(64, 2)
        buf.putInt(68, 112 + strings.size * 4)
        buf.putInt(96, 1)
        buf.putInt(100, 112 + strings.size * 4 + 8)

        for (i in strings.indices) {
            buf.putInt(112 + i * 4, strOffsets[i])
        }
        val typeOff = 112 + strings.size * 4
        buf.putInt(typeOff, 0)
        buf.putInt(typeOff + 4, 1)

        val clsOff = typeOff + 8
        buf.putInt(clsOff, 0)
        buf.putInt(clsOff + 4, 0x0001)
        buf.putInt(clsOff + 8, 1)
        buf.putInt(clsOff + 16, 2)

        System.arraycopy(strDataBytes, 0, dex, stringDataBaseOffset, strDataBytes.size)
        DexBinaryParser.recomputeDexChecksums(dex)
        return dex
    }
}
