package com.shieldforge.app.apk.signing

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Pure-Kotlin ASN.1 DER encoder for X.509 v3 self-signed certificates
 * and PKCS#7 / CMS SignedData blocks used in JAR v1 (META-INF/SHIELD.RSA) signing.
 */
object DerEncoder {
    private val OID_RSA_ENCRYPTION = intArrayOf(1, 2, 840, 113549, 1, 1, 1)
    private val OID_SHA256_WITH_RSA = intArrayOf(1, 2, 840, 113549, 1, 1, 11)
    private val OID_SHA256 = intArrayOf(2, 16, 840, 1, 101, 3, 4, 2, 1)
    private val OID_PKCS7_DATA = intArrayOf(1, 2, 840, 113549, 1, 7, 1)
    private val OID_PKCS7_SIGNED_DATA = intArrayOf(1, 2, 840, 113549, 1, 7, 2)
    private val OID_COMMON_NAME = intArrayOf(2, 5, 4, 3)
    private val OID_ORG_NAME = intArrayOf(2, 5, 4, 10)

    fun generateSelfSignedX509(
        commonName: String,
        organization: String,
        publicKey: PublicKey,
        privateKey: PrivateKey,
        validityDays: Int = 3650,
    ): X509Certificate {
        val now = System.currentTimeMillis()
        val notBefore = Date(now - 60_000L)
        val notAfter = Date(now + validityDays.toLong() * 86_400_000L)
        val serial = BigInteger(63, java.security.SecureRandom()).abs().max(BigInteger.ONE)

        val version = explicitTag(0, derInteger(BigInteger.valueOf(2))) // v3
        val serialBytes = derInteger(serial)
        val sigAlg = derSequence(derOid(OID_SHA256_WITH_RSA), derNull())
        val name = buildX500Name(commonName, organization)
        val validity = derSequence(derUtcTime(notBefore), derUtcTime(notAfter))
        val spki = publicKey.encoded

        val tbsCert = derSequence(version, serialBytes, sigAlg, name, validity, name, spki)

        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey)
        signer.update(tbsCert)
        val sigBytes = signer.sign()

        val fullCert = derSequence(tbsCert, sigAlg, derBitString(sigBytes))
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(fullCert)) as X509Certificate
    }

    fun buildPkcs7SignedData(
        sfContent: ByteArray,
        certificate: X509Certificate,
        privateKey: PrivateKey,
    ): ByteArray {
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey)
        signer.update(sfContent)
        val signatureBytes = signer.sign()

        val digestAlgId = derSequence(derOid(OID_SHA256), derNull())
        val digestAlgsSet = derSet(digestAlgId)
        val contentInfo = derSequence(derOid(OID_PKCS7_DATA))
        val certificates = explicitTag(0, certificate.encoded)

        val issuerAndSerial = derSequence(
            certificate.issuerX500Principal.encoded,
            derInteger(certificate.serialNumber),
        )
        val sigAlgId = derSequence(derOid(OID_RSA_ENCRYPTION), derNull())
        val signerInfo = derSequence(
            derInteger(BigInteger.ONE), // version 1
            issuerAndSerial,
            digestAlgId,
            sigAlgId,
            derOctetString(signatureBytes),
        )
        val signerInfos = derSet(signerInfo)

        val signedData = derSequence(
            derInteger(BigInteger.ONE),
            digestAlgsSet,
            contentInfo,
            certificates,
            signerInfos,
        )

        return derSequence(
            derOid(OID_PKCS7_SIGNED_DATA),
            explicitTag(0, signedData),
        )
    }

    private fun buildX500Name(cn: String, org: String): ByteArray {
        val orgRdn = derSet(derSequence(derOid(OID_ORG_NAME), derUtf8String(org)))
        val cnRdn = derSet(derSequence(derOid(OID_COMMON_NAME), derUtf8String(cn)))
        return derSequence(orgRdn, cnRdn)
    }

    private fun derSequence(vararg items: ByteArray): ByteArray = wrapTag(0x30, concat(*items))
    private fun derSet(vararg items: ByteArray): ByteArray = wrapTag(0x31, concat(*items))
    private fun explicitTag(tagNo: Int, inner: ByteArray): ByteArray = wrapTag(0xA0 or tagNo, inner)
    private fun derNull(): ByteArray = byteArrayOf(0x05, 0x00)
    private fun derOctetString(data: ByteArray): ByteArray = wrapTag(0x04, data)
    private fun derUtf8String(text: String): ByteArray = wrapTag(0x0C, text.toByteArray(Charsets.UTF_8))

    private fun derInteger(value: BigInteger): ByteArray = wrapTag(0x02, value.toByteArray())

    private fun derBitString(bytes: ByteArray): ByteArray {
        val out = ByteArray(bytes.size + 1)
        out[0] = 0x00
        System.arraycopy(bytes, 0, out, 1, bytes.size)
        return wrapTag(0x03, out)
    }

    private fun derUtcTime(date: Date): ByteArray {
        val fmt = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        return wrapTag(0x17, fmt.format(date).toByteArray(Charsets.US_ASCII))
    }

    private fun derOid(parts: IntArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(parts[0] * 40 + parts[1])
        for (i in 2 until parts.size) {
            writeBase128(out, parts[i])
        }
        return wrapTag(0x06, out.toByteArray())
    }

    private fun writeBase128(out: ByteArrayOutputStream, value: Int) {
        if (value < 0x80) {
            out.write(value)
            return
        }
        val stack = IntArray(5)
        var n = 0
        var v = value
        while (v > 0) {
            stack[n++] = v and 0x7F
            v = v ushr 7
        }
        for (i in n - 1 downTo 0) {
            val b = if (i == 0) stack[i] else (stack[i] or 0x80)
            out.write(b)
        }
    }

    private fun wrapTag(tag: Int, payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        val len = payload.size
        when {
            len < 128 -> out.write(len)
            len <= 0xFF -> {
                out.write(0x81)
                out.write(len)
            }
            len <= 0xFFFF -> {
                out.write(0x82)
                out.write((len shr 8) and 0xFF)
                out.write(len and 0xFF)
            }
            else -> {
                out.write(0x84)
                out.write((len shr 24) and 0xFF)
                out.write((len shr 16) and 0xFF)
                out.write((len shr 8) and 0xFF)
                out.write(len and 0xFF)
            }
        }
        out.write(payload)
        return out.toByteArray()
    }

    private fun concat(vararg chunks: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        for (c in chunks) out.write(c)
        return out.toByteArray()
    }
}
