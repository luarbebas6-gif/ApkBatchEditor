package com.user.apkeditor

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.user.apkeditor.databinding.ActivityMainBinding
import java.io.File
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var pickedApkUris: List<Uri> = emptyList()
    private var pickedIconBytes: ByteArray? = null

    private val pickApksLauncher = registerForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        pickedApkUris = uris
        binding.txtApkCount.text = "${uris.size} APK dipilih"
    }

    private val pickIconLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            pickedIconBytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
            binding.txtIcon.text = "Ikon dipilih (${pickedIconBytes?.size ?: 0} bytes)"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnPickApks.setOnClickListener {
            pickApksLauncher.launch(arrayOf("application/vnd.android.package-archive"))
        }

        binding.btnPickIcon.setOnClickListener {
            pickIconLauncher.launch(arrayOf("image/png"))
        }

        binding.btnProcess.setOnClickListener {
            processAll()
        }
    }

    private fun appendLog(msg: String) {
        runOnUiThread {
            binding.txtLog.text = "${binding.txtLog.text}\n$msg"
        }
    }

        private fun processAll() {
        if (pickedApkUris.isEmpty()) {
            appendLog("Pilih minimal satu APK dulu.")
            return
        }

        val findText = binding.editFindText.text.toString().ifBlank { null }
        val replaceText = binding.editReplaceText.text.toString().ifBlank { null }
        val options = ApkEditor.EditOptions(
            newIconBytes = pickedIconBytes,
            findText = findText,
            replaceText = replaceText
        )

        binding.txtLog.text = "Mulai memproses ${pickedApkUris.size} APK..."
        binding.btnProcess.isEnabled = false

        thread {
            try {
                val outDir = File(
                    getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS),
                    "edited_apks"
                ).apply { mkdirs() }

                appendLog("Menyiapkan kunci sign...")
                val keystoreFile = File(filesDir, "signing.p12")
                val (privateKey, cert) = ApkEditor.getOrCreateSigningKey(keystoreFile)
                appendLog("Kunci sign siap.")

                for ((index, uri) in pickedApkUris.withIndex()) {
                    try {
                        val inputFile = File(cacheDir, "input_$index.apk")
                        contentResolver.openInputStream(uri)?.use { input ->
                            inputFile.outputStream().use { output -> input.copyTo(output) }
                        }

                        val originalName = queryDisplayName(uri) ?: "apk_$index.apk"
                        val outputFile = File(outDir, "edited_$originalName")

                        appendLog("[$originalName] Mengedit...")
                        ApkEditor.editApk(inputFile, outputFile, options) { appendLog("  $it") }

                        appendLog("[$originalName] Menandatangani ulang...")
                        ApkEditor.signApk(outputFile, privateKey, cert) { appendLog("  $it") }

                        appendLog("[$originalName] -> Selesai: ${outputFile.absolutePath}")
                    } catch (e: Exception) {
                        appendLog("Gagal memproses index $index: ${e.javaClass.simpleName}: ${e.message}")
                    }
                }

                appendLog("\nSemua selesai. Hasil ada di folder:\n${outDir.absolutePath}")
            } catch (e: Throwable) {
                appendLog("ERROR FATAL: ${e.javaClass.simpleName}: ${e.message}")
                appendLog(e.stackTraceToString().take(2000))
            } finally {
                runOnUiThread { binding.btnProcess.isEnabled = true }
            }
        }
        }
