
package com.example.adguardcertcopy

import android.app.AlertDialog
import android.net.Uri
import android.os.Bundle
import android.os.CountDownTimer
import android.text.InputType
import android.text.TextWatcher
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
import okhttp3.*
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*

class MainActivity : ComponentActivity() {

    private lateinit var binding: ActivityMainBinding

    private val destDir  = "/data/adb/modules/adguardcert/system/etc/security/cacerts"
    private val destPath = "$destDir/9a5ba575.0"
    
    // OkHttp client for downloading certificates
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

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
        binding.btnDownloadFromUrl.setOnClickListener {
            showBurpSuiteDownloadDialog()
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
                // promptSaveCert(pemFile) { applyCertWithoutReboot() }
                promptSaveCert(pemFile) { startRebootCountdown(3) }
            } else {
                val err = (result.out + result.err).joinToString("\n")
                setStatus("Lỗi khi thực thi lệnh root.\n$err")
                setButtonsEnabled(true)
            }
        } catch (e: Exception) {
            setStatus("Lỗi: ${e.message ?: e.toString()}")
            setButtonsEnabled(true)
        }
    }

    private fun applyCertWithoutReboot() {
        setStatus("Đang inject chứng chỉ vào hệ thống...")
        binding.tvCountdown.text = "⏳ Đang xử lý..."

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val certFileName = destPath.substringAfterLast("/")
                val tempDir = "/data/local/tmp/tmp-ca-copy"
                val systemCerts = "/system/etc/security/cacerts"
                val apexCerts = "/apex/com.android.conscrypt/cacerts"
                
                val script = """
#!/system/bin/sh
rm -rf $tempDir
mkdir -p -m 700 $tempDir
cp $apexCerts/* $tempDir/ 2>/dev/null || cp $systemCerts/* $tempDir/ 2>/dev/null || true
mount -t tmpfs tmpfs $systemCerts
mv $tempDir/* $systemCerts/ 2>/dev/null || true
cp $destPath $systemCerts/$certFileName
chown root:root $systemCerts/*
chmod 644 $systemCerts/*
chcon u:object_r:system_file:s0 $systemCerts/*
rm -rf $tempDir

ZYGOTE_PID=${'$'}(pidof zygote || true)
ZYGOTE64_PID=${'$'}(pidof zygote64 || true)

for Z_PID in ${'$'}ZYGOTE_PID ${'$'}ZYGOTE64_PID; do
    [ -n "${'$'}Z_PID" ] && nsenter --mount=/proc/${'$'}Z_PID/ns/mnt -- /bin/mount --bind $systemCerts $apexCerts 2>/dev/null
done

APP_PIDS=${'$'}(echo "${'$'}ZYGOTE_PID ${'$'}ZYGOTE64_PID" | xargs -n1 ps -o 'PID' -P 2>/dev/null | grep -v PID || true)
for PID in ${'$'}APP_PIDS; do
    nsenter --mount=/proc/${'$'}PID/ns/mnt -- /bin/mount --bind $systemCerts $apexCerts 2>/dev/null &
done
wait
""".trimIndent()
                
                val scriptPath = "/data/local/tmp/inject_cert.sh"
                Shell.cmd("cat > $scriptPath << 'EOFSCRIPT'\n$script\nEOFSCRIPT").exec()
                Shell.cmd("chmod 755 $scriptPath").exec()
                val result = Shell.cmd("nsenter -t 1 -m -- sh $scriptPath").exec()
                Shell.cmd("rm -f $scriptPath").exec()
                
                val success = Shell.cmd("nsenter -t 1 -m -- ls $systemCerts/$certFileName").exec().isSuccess
                
                runOnUiThread {
                    if (success) {
                        setStatus("✅ Đã inject chứng chỉ thành công!\n\nChứng chỉ đã được áp dụng cho tất cả ứng dụng.")
                        binding.tvCountdown.text = "✅ Hoàn tất!"
                    } else {
                        val err = (result.out + result.err).joinToString("\n")
                        setStatus("❌ Lỗi khi inject chứng chỉ:\n$err")
                        binding.tvCountdown.text = "❌ Thất bại"
                    }
                    setButtonsEnabled(true)
                }
            } catch (e: Exception) {
                runOnUiThread {
                    setStatus("❌ Lỗi: ${e.message}")
                    binding.tvCountdown.text = "❌ Inject thất bại"
                    setButtonsEnabled(true)
                }
            }
        }
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
        binding.btnDownloadFromUrl.isEnabled = enabled
        binding.btnSaved.isEnabled = enabled
    }

    private fun showBurpSuiteDownloadDialog() {
        // Create custom layout for IP and Port inputs
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(50, 20, 50, 20)
        }
        
        val ipInput = EditText(this).apply {
            hint = "IP Address (ví dụ: 192.168.4.100)"
            inputType = InputType.TYPE_CLASS_TEXT
            setText("192.168.4.100") // Default IP
        }
        
        val portInput = EditText(this).apply {
            hint = "Port (ví dụ: 8080)"
            inputType = InputType.TYPE_CLASS_NUMBER
            setText("8080") // Default Burp Suite port
        }
        
        container.addView(android.widget.TextView(this).apply {
            text = "IP Address:"
            setPadding(0, 0, 0, 10)
        })
        container.addView(ipInput)
        
        container.addView(android.widget.TextView(this).apply {
            text = "Port:"
            setPadding(0, 20, 0, 10)
        })
        container.addView(portInput)
        
        AlertDialog.Builder(this)
            .setTitle("Tải chứng chỉ từ Burp Suite")
            .setMessage("Nhập thông tin Burp Suite để tải chứng chỉ CA:")
            .setView(container)
            .setPositiveButton("Tải") { _, _ ->
                val ip = ipInput.text?.toString()?.trim() ?: ""
                val port = portInput.text?.toString()?.trim() ?: ""
                if (ip.isNotEmpty() && port.isNotEmpty()) {
                    downloadCertificateFromBurpSuite(ip, port)
                } else {
                    Toast.makeText(this, "Vui lòng nhập đầy đủ IP và Port", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    private fun downloadCertificateFromBurpSuite(ip: String, port: String) {
        setButtonsEnabled(false)
        setStatus("Đang tải chứng chỉ từ Burp Suite ($ip:$port)...")

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val certUrl = "http://$ip:$port/cert"
                val certData = downloadBurpSuiteCertificate(certUrl)

                runOnUiThread {
                    processBurpSuiteCertificateData(certData, ip, port)
                }
            } catch (e: Exception) {
                runOnUiThread {
                    setStatus("Lỗi khi tải chứng chỉ từ Burp Suite: ${e.message}")
                    setButtonsEnabled(true)
                }
            }
        }
    }

    private suspend fun downloadBurpSuiteCertificate(certUrl: String): ByteArray = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(certUrl)
            .build()

        val response = httpClient.newCall(request).execute()
        if (!response.isSuccessful) {
            throw IOException("Không thể tải chứng chỉ từ Burp Suite. Kiểm tra:\n" +
                    "1. Burp Suite đang chạy\n" +
                    "2. IP và Port đúng\n" +
                    "3. Proxy listener đã bật\n" +
                    "Mã lỗi: ${response.code}")
        }
        
        response.body?.bytes() ?: throw IOException("Phản hồi rỗng từ Burp Suite")
    }

    private fun processBurpSuiteCertificateData(certData: ByteArray, ip: String, port: String) {
        try {
            val tempFile = File(cacheDir, "burp_cert.tmp")
            tempFile.writeBytes(certData)

            // Burp Suite typically serves DER format certificates
            processDownloadedCert(tempFile, sourceName = "Burp Suite ($ip:$port)")
        } catch (e: Exception) {
            setStatus("Lỗi khi xử lý chứng chỉ từ Burp Suite: ${e.message}")
            setButtonsEnabled(true)
        }
    }

    private fun processDownloadedCert(certFile: File, sourceName: String = "Downloaded Certificate") {
        try {
            val uri = Uri.fromFile(certFile)
            setStatus("Đang xử lý chứng chỉ từ $sourceName...")
            processAndCopy(uri, null)
        } catch (e: Exception) {
            setStatus("Lỗi khi xử lý chứng chỉ từ $sourceName: ${e.message}")
            setButtonsEnabled(true)
        }
    }


    private fun sanitizeName(raw: String): String {
        var s = raw.trim().lowercase()
        s = s.map { c ->
            when {
                c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' ||
                        c == '"' || c == '<' || c == '>' || c == '|' || c.code in 0..31 -> '_'
                else -> c
            }
        }.joinToString("")
        s = s.replace(Regex("\\s+"), " ")
        if (s.isEmpty()) s = "cert-" + System.currentTimeMillis().toString()
        if (s.length > 60) s = s.substring(0, 60)
        return s
    }


// ===================== Saved certificates ======================

    private fun savedDir(): File = File(filesDir, "saved_certs").apply { if (!exists()) mkdirs() }

    private fun listSavedNames(): List<String> {
        val dir = savedDir()
        return dir.listFiles()?.filter { it.isFile && it.name.endsWith(".pem") }?.map { file ->
            val md5 = calculateMd5(file)
            "${file.nameWithoutExtension} [$md5]"
        }?.sorted() ?: emptyList()
    }

    private fun calculateMd5(file: File): String {
        val md = MessageDigest.getInstance("MD5")
        file.inputStream().use { fis ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (fis.read(buffer).also { bytesRead = it } != -1) {
                md.update(buffer, 0, bytesRead)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }.substring(0, 10)
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
        showCertManagementDialog(names)
    }

    private fun showCertManagementDialog(originalNames: List<String>) {
        val container = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(20, 20, 20, 20)
        }

        // Search input
        val searchInput = EditText(this).apply {
            hint = "Tìm kiếm chứng chỉ..."
            inputType = InputType.TYPE_CLASS_TEXT
            setPadding(16, 16, 16, 16)
        }
        container.addView(searchInput)

        // Add some spacing
        container.addView(android.widget.Space(this).apply {
            minimumHeight = 20
        })

        // Create ListView for certificates with scroll support
        val listView = android.widget.ListView(this).apply {
            layoutParams = android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                400 // Fixed height to enable scrolling
            )
        }
        container.addView(listView)

        var filteredNames = originalNames.toMutableList()
        val adapter = android.widget.ArrayAdapter(this, android.R.layout.simple_list_item_1, filteredNames)
        listView.adapter = adapter

        // Create dialog first so we can reference it in callbacks
        lateinit var dialog: AlertDialog

        searchInput.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                val query = s?.toString()?.lowercase() ?: ""
                filteredNames.clear()
                if (query.isEmpty()) {
                    filteredNames.addAll(originalNames)
                } else {
                    filteredNames.addAll(originalNames.filter { it.lowercase().contains(query) })
                }
                adapter.notifyDataSetChanged()
            }
        })

        listView.setOnItemClickListener { _, _, position, _ ->
            if (position < filteredNames.size) {
                val selectedName = filteredNames[position]
                showCertOptionsDialog(selectedName, onInstall = {
                    dialog.dismiss()
                }, onDelete = {
                    val updatedNames = listSavedNames()
                    if (updatedNames.isEmpty()) {
                        Toast.makeText(this, "Không còn chứng chỉ nào được lưu.", Toast.LENGTH_SHORT).show()
                        dialog.dismiss()
                        return@showCertOptionsDialog
                    }
                    filteredNames.clear()
                    val currentQuery = searchInput.text?.toString()?.lowercase() ?: ""
                    if (currentQuery.isEmpty()) {
                        filteredNames.addAll(updatedNames)
                    } else {
                        filteredNames.addAll(updatedNames.filter { it.lowercase().contains(currentQuery) })
                    }
                    adapter.notifyDataSetChanged()
                })
            }
        }

        dialog = AlertDialog.Builder(this)
            .setTitle("Quản lý chứng chỉ đã lưu (${originalNames.size} chứng chỉ)")
            .setView(container)
            .setNegativeButton("Đóng", null)
            .create()
        dialog.show()
    }

    private fun showCertOptionsDialog(certName: String, onInstall: () -> Unit, onDelete: () -> Unit) {
        val actualName = certName.substringBefore(" [")
        AlertDialog.Builder(this)
            .setTitle("Chọn thao tác cho: $actualName")
            .setItems(arrayOf("Cài đặt chứng chỉ", "Xóa chứng chỉ")) { _, which ->
                when (which) {
                    0 -> {
                        installFromSaved(actualName)
                        onInstall()
                    }
                    1 -> {
                        confirmDeleteCert(actualName, onDelete)
                    }
                }
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    private fun confirmDeleteCert(certName: String, onActionComplete: () -> Unit) {
        AlertDialog.Builder(this)
            .setTitle("Xác nhận xóa")
            .setMessage("Bạn có chắc chắn muốn xóa chứng chỉ \"$certName\"?\n\nHành động này không thể hoàn tác.")
            .setPositiveButton("Xóa") { _, _ ->
                deleteSavedCert(certName)
                onActionComplete()
            }
            .setNegativeButton("Hủy", null)
            .show()
    }

    private fun deleteSavedCert(certName: String) {
        try {
            val file = File(savedDir(), "$certName.pem")
            if (file.exists() && file.delete()) {
                Toast.makeText(this, "Đã xóa chứng chỉ: $certName", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Không thể xóa chứng chỉ: $certName", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Lỗi khi xóa chứng chỉ: ${e.message}", Toast.LENGTH_LONG).show()
        }
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
                // applyCertWithoutReboot()
                startRebootCountdown(3)
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
            sb.append(b64.substring(i, e)).append("\n")
            i = e
        }
        return sb.toString()
    }

    private fun derToPem(der: ByteArray): String {
        val b64 = Base64.encodeToString(der, Base64.NO_WRAP)
        return "-----BEGIN CERTIFICATE-----\n" + wrap64(b64) + "-----END CERTIFICATE-----\n"
    }

    private fun x509FromDer(der: ByteArray): X509Certificate {
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    private fun x509FromPemBlock(block: String): X509Certificate {
        val cf = CertificateFactory.getInstance("X.509")
        val norm = block.replace("\r\n", "\n").replace("\r", "\n")
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
            val text = bytes.toString(Charsets.US_ASCII).replace("\r\n", "\n").replace("\r", "\n")
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
            outFile.writeText(chosen!! + "\n", Charsets.US_ASCII)
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

    override fun onDestroy() {
        super.onDestroy()
        // Clean up HTTP client resources
        httpClient.dispatcher.executorService.shutdown()
        httpClient.connectionPool.evictAll()
    }
}
