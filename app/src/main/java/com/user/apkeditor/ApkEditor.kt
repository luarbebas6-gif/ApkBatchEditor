package com.user.apkeditor

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.*
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Security
import java.security.cert.X509Certificate
import java.util.*
import java.util.zip.*
import android.util.Base64 as AndroidBase64

object ApkEditor {

    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    data class EditOptions(
        val newIconBytes: ByteArray? = null,
        val findText: String? = null,
        val replaceText: String? = null
    )

    fun editApk(input: File, output: File, options: EditOptions, log: (String) -> Unit) {
        ZipFile(input).use { zip ->
            ZipOutputStream(BufferedOutputStream(FileOutputStream(output))).use { out ->
                val entries = zip.entries().toList()
                for (entry in entries) {
                    if (entry.name.startsWith("META-INF/") &&
                        (entry.name.endsWith(".SF") || entry.name.endsWith(".RSA") ||
                         entry.name.endsWith(".DSA") || entry.name == "META-INF/MANIFEST.MF")) {
                        continue
                    }

                    val isIconFile = options.newIconBytes != null &&
                        Regex("res/mipmap.*ic_launcher.*\\.png$").containsMatchIn(entry.name)

                    val bytes: ByteArray = when {
                        isIconFile -> {
                            log("Mengganti ikon: ${entry.name}")
                            options.newIconBytes!!
                        }
                        entry.name.startsWith("assets/") && !entry.isDirectory &&
                            options.findText != null && options.replaceText != null -> {
                            val original = zip.getInputStream(entry).readBytes()
                            val text = runCatching { String(original, Charsets.UTF_8) }.getOrNull()
                            if (text != null && text.contains(options.findText)) {
                                log("Mengganti teks di: ${entry.name}")
                                text.replace(options.findText, options.replaceText).toByteArray(Charsets.UTF_8)
                            } else original
                        }
                        else -> zip.getInputStream(entry).readBytes()
                    }

                    val newEntry = ZipEntry(entry.name)
                    newEntry.method = ZipEntry.DEFLATED
                    out.putNextEntry(newEntry)
                    out.write(bytes)
                    out.closeEntry()
                }
            }
        }
    }

    fun getOrCreateSigningKey(keystoreFile: File): Pair<java.security.PrivateKey, X509Certificate> {
        if (keystoreFile.exists()) {
            val ks = java.security.KeyStore.getInstance("PKCS12")
            FileInputStream(keystoreFile).use { ks.load(it, "apkeditor".toCharArray()) }
            val alias = ks.aliases().nextElement()
            val key = ks.getKey(alias, "apkeditor".toCharArray()) as java.security.PrivateKey
            val cert = ks.getCertificate(alias) as X509Certificate
            return key to cert
        }

        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.generateKeyPair()

        val now = Date()
        val notAfter = Date(now.time + 1000L * 60 * 60 * 24 * 365 * 30)
        val serial = BigInteger(64, java.security.SecureRandom())
        val name = X500Name("CN=APK Batch Editor, O=Self Signed")

        val certBuilder = X509v3CertificateBuilder(
            name, serial, now, notAfter, name,
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        )
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val certHolder = certBuilder.build(signer)
        val cert = JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder)

        val ks = java.security.KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("apkeditorkey", keyPair.private, "apkeditor".toCharArray(), arrayOf(cert))
        FileOutputStream(keystoreFile).use { ks.store(it, "apkeditor".toCharArray()) }

        return keyPair.private to cert
    }

    fun signApk(apkFile: File, privateKey: java.security.PrivateKey, cert: X509Certificate, log: (String) -> Unit) {
        val tempSigned = File(apkFile.parentFile, apkFile.name + ".signed")

        val entries = LinkedHashMap<String, ByteArray>()
        ZipFile(apkFile).use { zf ->
            zf.entries().asSequence().filter { !it.isDirectory }.forEach { e ->
                entries[e.name] = zf.getInputStream(e).readBytes()
            }
        }

        val manifest = StringBuilder("Manifest-Version: 1.0\r\nCreated-By: ApkBatchEditor\r\n\r\n")
        val sha256 = MessageDigest.getInstance("SHA-256")
        for ((name, data) in entries) {
            val digest = AndroidBase64Encode(sha256.digest(data))
            manifest.append("Name: $name\r\n")
            manifest.append("SHA-256-Digest: $digest\r\n\r\n")
        }
        val manifestBytes = manifest.toString().toByteArray(Charsets.UTF_8)

        val sf = StringBuilder("Signature-Version: 1.0\r\nCreated-By: ApkBatchEditor\r\n")
        sf.append("SHA-256-Digest-Manifest: ${AndroidBase64Encode(sha256.digest(manifestBytes))}\r\n\r\n")
        val manifestSections = manifest.toString().split("\r\n\r\n").drop(1).filter { it.isNotBlank() }
        for (section in manifestSections) {
            val name = section.lineSequence().first().removePrefix("Name: ")
            val sectionBytes = (section + "\r\n\r\n").toByteArray(Charsets.UTF_8)
            sf.append("Name: $name\r\n")
            sf.append("SHA-256-Digest: ${AndroidBase64Encode(sha256.digest(sectionBytes))}\r\n\r\n")
        }
        val sfBytes = sf.toString().toByteArray(Charsets.UTF_8)

        val gen = CMSSignedDataGenerator()
        val signerBuilder = JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA256withRSA", privateKey, cert)
        gen.addSignerInfoGenerator(signerBuilder)
        gen.addCertificate(org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(cert))
        val signedData = gen.generate(CMSProcessableByteArray(sfBytes), false)
        val rsaBytes = signedData.encoded

        ZipOutputStream(BufferedOutputStream(FileOutputStream(tempSigned))).use { out ->
            fun writeEntry(name: String, data: ByteArray) {
                val e = ZipEntry(name)
                e.method = ZipEntry.DEFLATED
                out.putNextEntry(e)
                out.write(data)
                out.closeEntry()
            }
            writeEntry("META-INF/MANIFEST.MF", manifestBytes)
            writeEntry("META-INF/CERT.SF", sfBytes)
            writeEntry("META-INF/CERT.RSA", rsaBytes)
            for ((name, data) in entries) {
                writeEntry(name, data)
            }
        }

        apkFile.delete()
        tempSigned.renameTo(apkFile)
        log("Selesai ditandatangani: ${apkFile.name}")
    }

    private fun AndroidBase64Encode(bytes: ByteArray): String =
        AndroidBase64.encodeToString(bytes, AndroidBase64.NO_WRAP)
}
