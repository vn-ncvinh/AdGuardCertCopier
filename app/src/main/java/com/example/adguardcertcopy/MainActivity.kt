
package com.example.adguardcertcopy

import android.app.AlertDialog
import android.net.Uri
import android.os.Bundle
import android.os.CountDownTimer
import android.text.InputType
import android.widget.EditText
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.example.adguardcertcopy.databinding.ActivityMainBinding
import com.topjohnwu.superuser.Shell
import java.io.ByteArrayInputStream
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import android.util.Base64

class MainActivity : ComponentActivity() {

    private lateinit var binding: ActivityMainBinding

    private val destDir  = "/data/adb/modules/adguardcert/system/etc/security/cacerts"
    private val destPath = "$destDir/9a5ba575.0"

    private val pickAny = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) {
            setStatus("Đã huỷ.")
            return@registerForActivityResult
        }
        if (looksLikePkcs12(uri)) {
            askPasswordAndProcess(uri)
        } else {
            processAndCopy(uri, null)
        }
    }

    private val pickP12 = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri == null) {
            setStatus("Đã huỷ.")
            return@registerForActivityResult
        }
        askPasswordAndProcess(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        Shell.enableVerboseLogging = false

        binding.btnPick.setOnClickListener {
            pickAny.launch(arrayOf(
                "application/x-x509-ca-cert",
                "application/pkix-cert",
                "application/x-pem-file",
                "application/x-pkcs12",
                "*/*"
            ))
        }
        binding.btnPickP12.setOnClickListener {
            pickP12.launch(arrayOf("application/x-pkcs12", "*/*"))
        }
        binding.btnSaved.setOnClickListener {
            showSavedListAndInstall()
        }
    }

    private fun looksLikePkcs12(uri: Uri): Boolean {
        val name = uri.lastPathSegment?.lowercase() ?: return false
        return name.endsWith(".p12") || name.endsWith(".pfx")
    }

    private fun askPasswordAndProcess(uri: Uri) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Mật khẩu PKCS#12"
        }
        AlertDialog.Builder(this)
            .setTitle("Nhập mật khẩu cho PKCS#12")
            .setView(input)
            .setPositiveButton("OK") { _, _ ->
                val pwd = input.text?.toString() ?: ""
                processAndCopy(uri, pwd)
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    private fun processAndCopy(uri: Uri, pkcs12Password: String?) {
        try {
            setButtonsEnabled(false)

            val pemFile = ensurePemFromUri(uri, pkcs12Password)

            val cmds = listOf(
                "mkdir -p \"$destDir\"",
                "cp \"${pemFile.absolutePath}\" \"$destPath\"",
                "chmod 0644 \"$destPath\"",
                "chown 0:0 \"$destPath\""
            )
            val result = Shell.cmd(*cmds.toTypedArray()).exec()
            if (result.isSuccess) {
                setStatus("Đã cài chứng chỉ thành công.\nĐường dẫn: $destPath")
                promptSaveCert(pemFile) { promptRestartAfterInstall() }
            } else {
                val err = (result.out + result.err).joinToString("\n")
                setStatus("Lỗi khi thực thi lệnh root.\n$err")
                setButtonsEnabled(true)
            }
            // Note: don't delete pemFile if user wants to save; we saved by copying.
            // Here we can safely delete temporary file.
            

        } catch (e: Exception) {
            setStatus("Lỗi: ${e.message ?: e.toString()}")
            setButtonsEnabled(true)
        }
    }

    private fun promptRestartAfterInstall() {
        AlertDialog.Builder(this)
            .setTitle("Khởi động lại thiết bị?")
            .setMessage("Chứng chỉ đã được cài đặt thành công!\n\n⚠️ LƯU Ý: Bạn cần khởi động lại thiết bị để các thay đổi được áp dụng hoàn toàn.")
            .setPositiveButton("Khởi động lại ngay") { _, _ ->
                startRebootCountdown(5)
            }
            .setNegativeButton("Để sau") { _, _ ->
                binding.tvCountdown.text = "💡 Nhắc nhở: Hãy khởi động lại thiết bị để chứng chỉ có hiệu lực!"
                setButtonsEnabled(true)
            }
            .setCancelable(false)
            .show()
    }

    private fun startRebootCountdown(seconds: Int) {
        binding.tvCountdown.text = "Sẽ khởi động lại sau ${seconds}s..."
        object : CountDownTimer((seconds * 1000).toLong(), 1000L) {
            override fun onTick(msLeft: Long) {
                val s = (msLeft / 1000).toInt()
                binding.tvCountdown.text = "Sẽ khởi động lại sau ${s}s..."
            }
            override fun onFinish() {
                binding.tvCountdown.text = "Đang khởi động lại..."
                val res = Shell.cmd(
                    "svc power reboot || reboot || setprop sys.powerctl reboot"
                ).exec()
                if (!res.isSuccess) {
                    Toast.makeText(this@MainActivity, "Không thể reboot tự động. Vui lòng reboot thủ công.", Toast.LENGTH_LONG).show()
                    setButtonsEnabled(true)
                }
            }
        }.start()
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        binding.btnPick.isEnabled = enabled
        binding.btnPickP12.isEnabled = enabled
        binding.btnSaved.isEnabled = enabled
    }


    private fun sanitizeName(raw: String): String {
        var s = raw.trim()
        // Thay các ký tự không hợp lệ & ký tự điều khiển (< 0x20) bằng '_'
        s = s.map { c ->
            when {
                c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' ||
                        c == '"' || c == '<' || c == '>' || c == '|' || c.code in 0..31 -> '_'
                else -> c
            }
        }.joinToString("")
        // Gom khoảng trắng liên tiếp
        s = s.replace(Regex("\\s+"), " ")
        if (s.isEmpty()) s = "cert-" + System.currentTimeMillis().toString()
        if (s.length > 60) s = s.substring(0, 60)
        return s
    }


// ===================== Saved certificates ======================

    private fun savedDir(): File = File(filesDir, "saved_certs").apply { if (!exists()) mkdirs() }

    private fun listSavedNames(): List<String> {
        val dir = savedDir()
        return dir.listFiles()?.filter { it.isFile && it.name.endsWith(".pem") }?.map { it.nameWithoutExtension }?.sorted() ?: emptyList()
    }

    private fun promptSaveCert(pemFile: File, onDone: () -> Unit = {}) {
            val input = EditText(this).apply {
                hint = "Tên chứng chỉ (ví dụ: Burp CA)"
            }
            AlertDialog.Builder(this)
                .setTitle("Lưu chứng chỉ vừa cài?")
                .setView(input)
                .setPositiveButton("Lưu") { _, _ ->
                    val raw = input.text?.toString() ?: ""
                    val name = sanitizeName(raw)
                    try {
                        val dir = savedDir()
                        val target = File(dir, "$name.pem")
                        // Ensure directory exists
                        if (!dir.exists()) dir.mkdirs()
                        pemFile.copyTo(target, overwrite = true)
                        Toast.makeText(this, "Đã lưu: ${target.name}", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Toast.makeText(this, "Không lưu được: ${e.message}", Toast.LENGTH_LONG).show()
                    } finally {
                        onDone()
                    }
                }
                .setNegativeButton("Không") { _, _ -> onDone() }
                .setCancelable(false)
                .show()
        }

        private fun showSavedListAndInstall() {
        val names = listSavedNames()
        if (names.isEmpty()) {
            Toast.makeText(this, "Chưa có chứng chỉ nào được lưu.", Toast.LENGTH_SHORT).show()
            return
        }
        AlertDialog.Builder(this)
            .setTitle("Chọn chứng chỉ đã lưu để cài")
            .setItems(names.toTypedArray()) { _, which ->
                val name = names[which]
                installFromSaved(name)
            }
            .setNegativeButton("Đóng", null)
            .show()
    }

    private fun installFromSaved(name: String) {
        try {
            val f = File(savedDir(), "$name.pem")
            if (!f.exists()) {
                Toast.makeText(this, "Không tìm thấy: $name", Toast.LENGTH_SHORT).show()
                return
            }

            setButtonsEnabled(false)
            val cmds = arrayOf(
                "mkdir -p \"$destDir\"",
                "cp \"${f.absolutePath}\" \"$destPath\"",
                "chmod 0644 \"$destPath\"",
                "chown 0:0 \"$destPath\""
            )
            val result = Shell.cmd(*cmds).exec()
            if (result.isSuccess) {
                setStatus("Đã cài từ chứng chỉ đã lưu: $name\n$destPath")
                promptRestartAfterInstall()
            } else {
                val err = (result.out + result.err).joinToString("\n")
                setStatus("Lỗi root khi cài từ chứng chỉ đã lưu.\n$err")
                setButtonsEnabled(true)
            }
        } catch (e: Exception) {
            setStatus("Lỗi khi cài từ chứng chỉ đã lưu: ${e.message}")
            setButtonsEnabled(true)
        }
    }

    // ===================== Cert parsing & conversion ======================

    private fun isPem(bytes: ByteArray): Boolean {
        val head = bytes.take(4096).toByteArray().toString(Charsets.US_ASCII)
        return head.contains("-----BEGIN CERTIFICATE-----")
    }

    private fun findPemBlocks(text: String): List<String> {
        val result = mutableListOf<String>()
        var idx = 0
        while (true) {
            val start = text.indexOf("-----BEGIN CERTIFICATE-----", idx)
            if (start < 0) break
            val end = text.indexOf("-----END CERTIFICATE-----", start)
            if (end < 0) break
            val block = text.substring(start, end + "-----END CERTIFICATE-----".length)
            result.add(block)
            idx = end + "-----END CERTIFICATE-----".length
        }
        return result
    }

    private fun wrap64(b64: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < b64.length) {
            val e = kotlin.math.min(i + 64, b64.length)
            sb.append(b64.substring(i, e)).append("\\n")
            i = e
        }
        return sb.toString()
    }

    private fun derToPem(der: ByteArray): String {
        val b64 = Base64.encodeToString(der, Base64.NO_WRAP)
        return "-----BEGIN CERTIFICATE-----\\n" + wrap64(b64) + "-----END CERTIFICATE-----\\n"
    }

    private fun x509FromDer(der: ByteArray): X509Certificate {
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    private fun x509FromPemBlock(block: String): X509Certificate {
        val cf = CertificateFactory.getInstance("X.509")
        val norm = block.replace("\\r\\n", "\\n").replace("\\r", "\\n")
        return cf.generateCertificate(ByteArrayInputStream(norm.toByteArray(Charsets.US_ASCII))) as X509Certificate
    }

    private fun isCA(cert: X509Certificate): Boolean {
        return try { cert.basicConstraints >= 0 } catch (_: Exception) { false }
    }

    private fun ensurePemFromUri(uri: Uri, pkcs12Password: String?): File {
        val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalStateException("Không đọc được dữ liệu từ file đã chọn.")

        val outFile = File(cacheDir, "upload_cert.pem")

        if (isPem(bytes)) {
            val text = bytes.toString(Charsets.US_ASCII).replace("\\r\\n", "\\n").replace("\\r", "\\n")
            val blocks = findPemBlocks(text)
            if (blocks.isEmpty()) throw IllegalArgumentException("PEM không chứa CERTIFICATE block.")
            var chosen: String? = null
            for (b in blocks) {
                try {
                    val x = x509FromPemBlock(b)
                    if (isCA(x)) { chosen = b; break }
                    if (chosen == null) chosen = b
                } catch (_: Exception) {}
            }
            outFile.writeText(chosen!!, Charsets.US_ASCII)
            return outFile
        }

        try {
            val derX = x509FromDer(bytes)
            val pem = derToPem(derX.encoded)
            outFile.writeText(pem, Charsets.US_ASCII)
            return outFile
        } catch (_: Exception) { /* fallthrough */ }

        if (pkcs12Password != null) {
            val ks = KeyStore.getInstance("PKCS12")
            ks.load(ByteArrayInputStream(bytes), pkcs12Password.toCharArray())
            val aliases = ks.aliases()
            var chosenCert: X509Certificate? = null
            while (aliases.hasMoreElements()) {
                val al = aliases.nextElement()
                val cert = ks.getCertificate(al)
                if (cert is X509Certificate) {
                    if (isCA(cert)) { chosenCert = cert; break }
                    if (chosenCert == null) chosenCert = cert
                }
            }
            if (chosenCert == null) throw IllegalArgumentException("Không tìm thấy certificate trong PKCS#12.")
            val pem = derToPem(chosenCert.encoded)
            outFile.writeText(pem, Charsets.US_ASCII)
            return outFile
        }

        throw IllegalArgumentException("Định dạng không hỗ trợ hoặc cần mật khẩu PKCS#12.")
    }

    private fun setStatus(msg: String) {
        binding.tvStatus.text = msg
    }
}
