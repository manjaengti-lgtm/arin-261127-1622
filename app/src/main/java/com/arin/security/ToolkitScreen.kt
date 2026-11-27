package com.arin.security

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.arin.terminal.Linux
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private data class ToolkitItem(val id: String, val name: String, val purpose: String, val check: String, val availability: String)

private val toolkitItems = listOf(
    ToolkitItem("jadx", "JADX", "Inspect/decompile Android DEX bytecode", "jadx", "Existing APK toolkit setup; runtime must be verified"),
    ToolkitItem("apktool", "Apktool", "Decode and rebuild APK resources", "apktool", "Existing APK toolkit setup; runtime must be verified"),
    ToolkitItem("androguard", "Androguard", "Static APK/DEX metadata and code analysis", "androguard", "Python environment; runtime must be verified"),
    ToolkitItem("nmap", "Nmap", "Scoped host and service discovery", "nmap", "Installable in Ubuntu/PRoot"),
    ToolkitItem("tshark", "TShark", "Offline packet-capture inspection", "tshark", "Installable; live capture may not work on Android"),
    ToolkitItem("wireshark-cli", "Wireshark CLI", "Read and analyse packet captures", "tshark", "Installable CLI package"),
    ToolkitItem("yara", "YARA", "Pattern-based file classification", "yara", "Installable in Ubuntu/PRoot"),
    ToolkitItem("clamav", "ClamAV", "Signature-based malware triage", "clamscan", "Installable; update signatures before use"),
    ToolkitItem("binwalk", "Binwalk", "Inspect firmware and embedded components", "binwalk", "Installable in Ubuntu/PRoot"),
    ToolkitItem("sleuthkit", "The Sleuth Kit", "Filesystem and forensic image analysis", "fls", "Installable in Ubuntu/PRoot"),
    ToolkitItem("sqlite3", "SQLite", "Inspect SQLite databases", "sqlite3", "Installable in Ubuntu/PRoot"),
    ToolkitItem("semgrep", "Semgrep", "Static application security analysis", "semgrep", "Optional pipx installation; may need extra disk/RAM"),
    ToolkitItem("bandit", "Bandit", "Python source security linting", "bandit", "Optional pipx installation"),
    ToolkitItem("shellcheck", "ShellCheck", "Static shell-script analysis", "shellcheck", "Installable in Ubuntu/PRoot"),
    ToolkitItem("trivy", "Trivy", "Dependency and artifact vulnerability scanning", "trivy", "Separate official installation; not installed by baseline"),
    ToolkitItem("testssl", "testssl.sh", "TLS configuration assessment", "testssl.sh", "Separate official installation; not installed by baseline"),
    ToolkitItem("owasp-zap", "OWASP ZAP", "Web application security analysis", "zap.sh", "Remote/desktop Linux recommended; not suitable for every phone"),
    ToolkitItem("kismet", "Kismet", "Wireless monitoring", "kismet", "Requires compatible wireless hardware and drivers")
)

@Composable
fun ToolkitScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var running by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var output by remember { mutableStateOf("") }
    var installed by remember { mutableStateOf(false) }
    var checks by remember { mutableStateOf<Map<String, Boolean>>(emptyMap()) }

    fun refresh() {
        scope.launch {
            running = true
            message = "Checking every catalogue tool in the connected execution environment…"
            try {
                val result = ToolPipeline.status(context)
                output = result.combined()
                checks = toolkitItems.associate { item ->
                    val row = output.lineSequence().firstOrNull { it.startsWith(item.id + ":") }
                    item.check to (row?.contains("COMMAND_RESPONDED") == true)
                }
                installed = true
                message = if (result.error == null) "Runtime checks completed. COMMAND_RESPONDED means a version/help command ran; NOT_LOCAL and MISSING_OR_FAILED are not working local tools." else "Verification error: ${result.error}"
            } catch (e: Exception) { message = "Verification failed: ${e.message}" }
            running = false
        }
    }

    Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Arin Security Toolkit", style = MaterialTheme.typography.titleLarge)
        Text("Every catalogue entry is connected to Arin's structured tool pipeline. Install, verify and run supported operations through the AI bridge. Version checks are smoke tests, not proof of full functionality.", style = MaterialTheme.typography.bodySmall)
        Text("The pipeline supports local static analysis and offline forensic tools, bounded authorised network diagnostics, and clear remote/hardware limitations. Tool execution from AI requires the existing per-action approval.", style = MaterialTheme.typography.bodySmall)
        if (!Linux.installed(context)) {
            Text("Built-in Linux is not installed. Open Arin Settings → Linux and install Ubuntu first.", color = MaterialTheme.colorScheme.error)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(enabled = !running && Linux.installed(context), onClick = {
                scope.launch {
                    running = true; message = "Preparing installer…"; output = ""
                    try {
                        val script = withContext(Dispatchers.IO) { context.assets.open("ARIN-TOOLKIT-ADDON/install-defensive-toolkit.sh").bufferedReader().use { it.readText() } }
                        val file = java.io.File(Linux.rootfs(context), "root/.arin/install-defensive-toolkit.sh")
                        file.parentFile?.mkdirs(); file.writeText(script); file.setExecutable(true)
                        message = "Installing compatible baseline tools… Keep Arin open."
                        val r = Linux.run(context, "bash /root/.arin/install-defensive-toolkit.sh", timeoutMs = 60 * 60_000L) { line -> output = (output + line + "\n").takeLast(16_000) }
                        output = r.combined().takeLast(16_000)
                        message = if (r.exitCode == 0 && r.error == null) "Installer finished. Tap Verify tools to check command presence." else "Installer reported an error (exit ${r.exitCode}): ${r.error ?: r.combined().takeLast(800)}"
                    } catch (e: Exception) { message = "Installation failed: ${e.message}" }
                    running = false
                }
            }) { Text("Install compatible tools") }
            OutlinedButton(enabled = !running, onClick = { refresh() }) { Text("Verify all 18 tools") }
            OutlinedButton(enabled = !running && Linux.installed(context), onClick = {
                scope.launch {
                    running = true; message = "Installing/updating the dedicated APK reverse-engineering suite…"; output = ""
                    try {
                        val r = Linux.installApkToolkit(context) { line -> output = (output + line + "\n").takeLast(16_000) }
                        output = r.combined().takeLast(16_000)
                        message = if (r.exitCode == 0 && r.error == null && r.combined().contains("APK_TOOLKIT_READY"))
                            "APK toolkit setup reports ready. Run Verify tools to test commands."
                        else "APK toolkit setup did not confirm readiness (exit ${r.exitCode}): ${r.error ?: r.combined().takeLast(700)}"
                    } catch (e: Exception) { message = "APK toolkit setup failed: ${e.message}" }
                    running = false
                }
            }) { Text("Install / update APK tools") }
        }
        if (running) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (message.isNotBlank()) Text(message, style = MaterialTheme.typography.bodySmall)
        toolkitItems.forEach { item ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(item.name, style = MaterialTheme.typography.titleSmall)
                        val present = checks[item.check]
                        if (present == true) Text("Present — see smoke-test result", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelSmall)
                        else if (present == false) Text("Not detected", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                        else Text("Not checked", style = MaterialTheme.typography.labelSmall)
                    }
                    Text(item.purpose, style = MaterialTheme.typography.bodySmall)
                    Text(item.availability, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    OutlinedButton(enabled = !running, onClick = {
                        scope.launch {
                            running = true
                            message = "Installing/checking ${item.name}…"
                            val r = runCatching { ToolPipeline.install(context, item.id) }
                                .getOrElse { com.arin.terminal.Termux.Result("", it.message ?: "Installation failed", 1, null) }
                            output = r.combined()
                            message = if (r.exitCode == 0 && r.error == null) "${item.name}: installer completed. Run Verify all 18 tools." else "${item.name}: ${r.error ?: r.stderr.ifBlank { r.stdout }.takeLast(500)}"
                            running = false
                        }
                    }) { Text("Install / check") }
                }
            }
        }
        if (output.isNotBlank()) {
            Text("Installer / smoke-test log", style = MaterialTheme.typography.titleSmall)
            Text(output.takeLast(12_000), style = MaterialTheme.typography.bodySmall)
        }
        Text("Platform limits: PRoot is not Android root. ZAP is remote/desktop Linux only in this build; Kismet requires compatible wireless hardware and drivers. Trivy and testssl.sh require official/manual setup. A command smoke test does not prove every analysis feature works; each run produces its own exit code and output.", style = MaterialTheme.typography.bodySmall)
    }
}
