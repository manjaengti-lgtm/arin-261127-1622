package com.arin.security

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.arin.chat.ChatViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/** A bounded investigation workflow using Arin's built-in offline and passive adapters. */
@Composable
fun AutopilotScreen(vm: ChatViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var request by rememberSaveable { mutableStateOf("") }
    var target by rememberSaveable { mutableStateOf("") }
    var permission by rememberSaveable { mutableStateOf(false) }
    var offline by remember { mutableStateOf(SecurityIntelligence.offlineMode(context)) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("") }
    var report by rememberSaveable { mutableStateOf("") }
    var selectedFilePath by rememberSaveable { mutableStateOf("") }

    val saveReport = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/markdown")) { uri: Uri? ->
        if (uri != null && report.isNotBlank()) runCatching {
            context.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(report) }
            status = "Report exported."
        }.onFailure { status = "Export failed: ${it.message}" }
    }
    val pickSource = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            busy = true; report = ""; status = "Copying selected file for bounded local analysis…"
            try {
                val f = withContext(Dispatchers.IO) {
                    val out = File(context.cacheDir, "arin-source-${System.currentTimeMillis()}-${uri.lastPathSegment?.takeLast(30) ?: "input"}")
                    context.contentResolver.openInputStream(uri)!!.use { input ->
                        out.outputStream().use { output ->
                            val buffer = ByteArray(64 * 1024)
                            var copied = 0L
                            while (true) {
                                val n = input.read(buffer)
                                if (n < 0) break
                                copied += n
                                require(copied <= 512L * 1024 * 1024) { "Selected file exceeds Arin's 512 MB analysis limit." }
                                output.write(buffer, 0, n)
                            }
                        }
                    }
                    out
                }
                selectedFilePath = f.absolutePath
                report = withContext(Dispatchers.IO) {
                    val signature = f.inputStream().use { input -> ByteArray(4).also { input.read(it) } }
                    val zipLike = signature.size >= 4 && signature[0] == 0x50.toByte() && signature[1] == 0x4B.toByte()
                    if (zipLike || f.extension.lowercase() in setOf("zip", "apk", "aab", "jar")) SourceAudit.analyseArchive(f) { status = it }
                    else {
                        val text = f.inputStream().bufferedReader().use { reader ->
                            val outText = StringBuilder(); val buffer = CharArray(8192); var total = 0
                            while (total < 2_000_000) { val n = reader.read(buffer, 0, minOf(buffer.size, 2_000_000 - total)); if (n < 0) break; outText.append(buffer, 0, n); total += n }
                            outText.toString()
                        }
                        SourceAudit.analyseText(f.name, text)
                    }
                }
                SecurityIntelligence.saveReport(context, report)
                status = "Offline analysis complete. No code was executed and the source file was not modified."
            } catch (e: Exception) { status = "Analysis failed: ${e.message}" }
            busy = false
        }
    }

    fun runNetworkCheck() {
        if (offline) { status = "Offline mode is enabled. Turn it off to run a network check."; return }
        if (!permission) { status = "Confirm that you own this target or have permission before running a network check."; return }
        if (target.isBlank()) { status = "Enter a website or API address first."; return }
        scope.launch {
            busy = true; report = ""; status = "Running passive web/API assessment…"
            report = withContext(Dispatchers.IO) { WebAudit.analyse(target) { status = it } }
            SecurityIntelligence.saveReport(context, report)
            ScopeLog.add(context, "Autopilot passive web assessment", target)
            ScopeLog.saveReport(context, "Autopilot web assessment", report)
            status = "Passive assessment finished. Only ordinary HTTP requests were used."
            busy = false
        }
    }

    Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Investigation Autopilot", style = MaterialTheme.typography.titleLarge)
        Text("Choose a target type. Arin selects a supported adapter, records what it did, and keeps the report on this phone. It never claims a tool is working unless it has been verified.", style = MaterialTheme.typography.bodySmall)
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Offline mode", modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                    Switch(checked = offline, onCheckedChange = { offline = it; SecurityIntelligence.setOfflineMode(context, it) })
                }
                Text(if (offline) "Enabled: local APK/source/evidence analysis only. Network adapters are disabled by this screen." else "Disabled: passive web checks can run after you confirm authorisation." , style = MaterialTheme.typography.bodySmall)
            }
        }
        Text("What are you investigating?", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(request, { request = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Optional objective / notes") }, minLines = 2)
        OutlinedButton(
            onClick = {
                val objective = request.ifBlank { "Plan a safe investigation using the selected target and the capabilities currently available in Arin." }
                val targetContext = if (target.isBlank()) "No network target supplied." else "Network target supplied: $target"
                val fileContext = if (selectedFilePath.isBlank()) "No file imported into Arin private storage." else "User-selected file imported into Arin private storage: $selectedFilePath. You may request apk_static for APK/AAB or source_audit for supported source/archive files, using this exact path. Do not access other paths."
                val permissionContext = if (permission) "The user confirms ownership or explicit permission for this target." else "No network authorisation has been confirmed; do not perform network assessment."
                val modeContext = if (offline) "Offline mode is enabled; do not propose network operations." else "Offline mode is disabled, but network actions still require explicit confirmation and existing approval gates."
                val taskId = runCatching { ReliabilityEngine.createTask(context, objective.take(180), objective) }.getOrNull()
                vm.newChat()
                vm.send("Plan this Arin security investigation. Do not claim to have executed anything. First classify the objective, select only capabilities that the live registry says exist, identify missing tools and platform constraints, and give a step-by-step plan. Separate actions Arin can perform now from actions requiring installation, a user-selected file, or further approval. Before reporting completion, evaluate actual tool exit codes and evidence; do not equate output with a verified finding. Update the persistent task ledger using approved task_update actions as progress changes.\n\nTask ID: ${taskId ?: "not created — report storage error"}\nObjective: $objective\n$targetContext\n$fileContext\n$permissionContext\n$modeContext\n\n" + SecurityIntelligence.modelCapabilityNote(context))
                vm.openChat = true
            },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth()
        ) { Text("Ask Arin AI to plan this investigation") }
        Text("The AI plans using the live capability registry. It does not silently run scans; local analysis and network actions remain behind their respective controls.", style = MaterialTheme.typography.bodySmall)
        Text("Supported workflows", style = MaterialTheme.typography.titleMedium)
        OutlinedButton(onClick = { pickSource.launch(arrayOf("*/*")) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text("Inspect APK / ZIP / source / dependency files")
        }
        Text("Imports the selected file into Arin private storage. The AI can then request an approved APK/static source adapter on that exact file. Archive contents are never executed.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(target, { target = it }, modifier = Modifier.fillMaxWidth(), singleLine = true, label = { Text("Website or API address") })
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = permission, onCheckedChange = { permission = it })
            Text("I own this target or have explicit permission to assess it.", style = MaterialTheme.typography.bodySmall)
        }
        Button(onClick = { runNetworkCheck() }, enabled = !busy && !offline && permission && target.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
            Text("Run passive web assessment")
        }
        OutlinedButton(onClick = {
            report = "# Arin capability and tool-adapter report\n\n${SecurityIntelligence.modelCapabilityNote(context)}\n\n## Current mode\n- Offline mode: $offline\n- Android version: ${android.os.Build.VERSION.RELEASE}\n- Device architecture: ${android.os.Build.SUPPORTED_ABIS.joinToString()}\n- Built-in Linux installed: ${com.arin.terminal.Linux.installed(context)}\n- APK toolkit marker: ${com.arin.terminal.Linux.apkToolkitReady(context)}\n- Android build environment ready: ${com.arin.terminal.Linux.androidBuildReady(context)}\n"
            SecurityIntelligence.saveReport(context, report)
            status = "Capability report generated and saved."
        }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Generate capability / environment report") }
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Reliability & investigation history", style = MaterialTheme.typography.titleMedium)
                Text("Run local integrity checks, inspect device resources and verify Arin's execution audit. These checks do not claim to validate the Android build or external AI connectivity.", style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        report = ReliabilityEngine.selfTest(context)
                        SecurityIntelligence.saveReport(context, report)
                        status = "Local reliability self-test finished."
                    }, enabled = !busy) { Text("Self-test") }
                    OutlinedButton(onClick = {
                        report = ReliabilityEngine.verifyAudit(context)
                        status = "Audit verification finished."
                    }, enabled = !busy) { Text("Verify audit") }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { report = ReliabilityEngine.resourceReport(context); status = "Resource snapshot generated." }, enabled = !busy) { Text("Device resources") }
                    OutlinedButton(onClick = { report = ReliabilityEngine.taskReport(context); status = "Task ledger loaded." }, enabled = !busy) { Text("Task ledger") }
                }
            }
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (status.isNotBlank()) Text(status, style = MaterialTheme.typography.bodySmall)
        if (report.isNotBlank()) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { saveReport.launch("arin-investigation-${System.currentTimeMillis()}.md") }) { Text("Export report") }
                TextButton(onClick = {
                    val clipboard = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                    clipboard.setPrimaryClip(android.content.ClipData.newPlainText("Arin investigation report", report))
                    status = "Report copied."
                }) { Text("Copy") }
                TextButton(onClick = {
                    vm.newChat()
                    vm.send("Explain this Arin security investigation report in plain English. Separate confirmed observations from heuristic matches, explain limitations, and suggest safe remediation. Do not claim unverified findings are confirmed.\n\n${report.take(18_000)}")
                    vm.openChat = true
                }) { Text("Ask Arin to explain") }
            }
            SelectionContainer { Text(report.take(24_000), style = MaterialTheme.typography.bodySmall) }
        }
        Text("Adapter status is capability-based, not a guarantee that third-party binaries are installed. Network tests are passive and require authorisation. Full SBOM resolution, dynamic sandbox execution and native reverse engineering require additional runtime components and are not represented as complete here.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
