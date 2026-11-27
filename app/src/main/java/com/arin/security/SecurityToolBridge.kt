package com.arin.security

import android.content.Context
import org.json.JSONObject
import com.arin.terminal.Shell
import com.arin.terminal.Termux
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Narrow, structured bridge between the primary model and Arin's built-in security adapters.
 * It intentionally does not expose arbitrary shell execution. Every network operation requires
 * explicit authorisation in the tool payload and is disabled while offline mode is enabled.
 */
object SecurityToolBridge {
    private const val MAX_INPUT_BYTES = 128L * 1024 * 1024

    suspend fun execute(context: Context, payload: String): Termux.Result {
        val request = runCatching { JSONObject(payload) }.getOrElse {
            return fail("Malformed security_tool JSON: ${it.message}")
        }
        val id = request.optString("id").trim()
        val args = request.optJSONObject("args") ?: JSONObject()
        val result = withContext(Dispatchers.IO) {
            try {
                when (id) {
                "capability_report" -> ok(SecurityIntelligence.modelCapabilityNote(context) +
                    "\n\nOffline mode: ${SecurityIntelligence.offlineMode(context)}")
                "network_info" -> ok(NetAudit.networkInfo(context))
                "evidence_verify" -> ok(Forensics.verifyAll(context))
                "vuln_lookup" -> {
                    require(!SecurityIntelligence.offlineMode(context)) { "Offline mode is enabled; vulnerability database lookup is disabled." }
                    val product = args.optString("product").trim()
                    val version = args.optString("version").trim()
                    require(product.isNotBlank() && product.length <= 120 && version.isNotBlank() && version.length <= 80) { "Provide a product and version." }
                    ok("# Vulnerability intelligence — $product $version\n_Matches are leads, not proof of exploitability; check vendor advisories and backports._\n\n" + VulnIntel.lookup(product, version))
                }
                "apk_static" -> {
                    val file = approvedLocalFile(context, args.optString("path"))
                    require(file.extension.equals("apk", true) || file.extension.equals("aab", true)) { "Expected an APK or AAB file." }
                    ok(ApkAudit.analyse(context, file))
                }
                "source_audit" -> {
                    val file = approvedLocalFile(context, args.optString("path"))
                    val report = if (file.extension.lowercase() in setOf("zip", "apk", "aab", "jar"))
                        SourceAudit.analyseArchive(file) else {
                        require(file.length() <= 4L * 1024 * 1024) { "Text source file exceeds 4 MB limit." }
                        SourceAudit.analyseText(file.name, file.readText())
                    }
                    ok(report)
                }
                "web_passive" -> {
                    require(!SecurityIntelligence.offlineMode(context)) { "Offline mode is enabled; network assessment is disabled." }
                    require(args.optBoolean("authorised", false)) { "Network assessment requires explicit owner/authorised-scope confirmation." }
                    val target = args.optString("target").trim()
                    require(target.isNotBlank() && target.length <= 2048) { "A valid target URL is required." }
                    val parsed = java.net.URL(if (target.startsWith("http://", true) || target.startsWith("https://", true)) target else "https://$target")
                    require(parsed.protocol in setOf("http", "https") && parsed.host.isNotBlank()) { "Only HTTP/HTTPS targets are supported." }
                    ok(WebAudit.analyse(parsed.toString()))
                }
                "reliability_self_test" -> ok(ReliabilityEngine.selfTest(context))
                "resource_report" -> ok(ReliabilityEngine.resourceReport(context))
                "audit_verify" -> ok(ReliabilityEngine.verifyAudit(context))
                "task_list" -> ok(ReliabilityEngine.taskReport(context))
                "task_create" -> {
                    val title = args.optString("title").trim()
                    val objective = args.optString("objective")
                    val taskId = ReliabilityEngine.createTask(context, title, objective)
                    ok("Task created. ID: $taskId\nStatus: PENDING. This records work; it does not execute it.")
                }
                "task_update" -> {
                    val taskId = args.optString("task_id").trim()
                    val status = args.optString("status").trim().uppercase()
                    ok(ReliabilityEngine.updateTask(context, taskId, status, args.optString("note")))
                }
                "result_evaluate" -> {
                    val exit = args.optInt("exit_code", -1)
                    ok(ReliabilityEngine.evaluateResult(exit, args.optString("stdout"), args.optString("stderr")))
                }
                "finding_correlate" -> ok(ReliabilityEngine.correlateFindings(args.optJSONArray("findings") ?: org.json.JSONArray()))
                "tool_catalogue" -> ok(ToolPipeline.catalogueReport(context))
                "tool_status" -> ToolPipeline.status(context)
                "tool_install" -> {
                    val tool = args.optString("tool").trim()
                    require(tool.isNotBlank()) { "Provide a catalogue tool ID." }
                    ToolPipeline.install(context, tool)
                }
                "tool_run" -> {
                    val tool = args.optString("tool").trim()
                    require(tool.isNotBlank()) { "Provide a catalogue tool ID." }
                    ToolPipeline.run(context, tool, args)
                }
                "tool_smoke_test" -> {
                    require(Shell.problem(context) == null) { "No Linux/Termux environment is configured." }
                    val tool = args.optString("tool").lowercase()
                    val checks = mapOf(
                        "nmap" to "nmap --version", "tshark" to "tshark --version", "wireshark" to "tshark --version",
                        "yara" to "yara --version", "clamscan" to "clamscan --version", "binwalk" to "binwalk --help",
                        "sqlite3" to "sqlite3 --version", "shellcheck" to "shellcheck --version", "bandit" to "bandit --version",
                        "semgrep" to "semgrep --version", "jadx" to "jadx --version", "apktool" to "apktool --version",
                        "trivy" to "trivy --version", "testssl" to "testssl.sh --version"
                    )
                    val command = checks[tool] ?: throw IllegalArgumentException("Tool is not in the smoke-test allowlist: $tool")
                    val result = Shell.run(context, "if command -v ${toolCommand(tool)} >/dev/null 2>&1; then $command; else echo 'NOT INSTALLED: ${toolCommand(tool)}' >&2; exit 127; fi", timeoutMs = 30_000L)
                    Termux.Result(result.stdout.take(12_000), result.stderr.take(4_000), result.exitCode, result.error)
                }
                    else -> fail("Unknown security adapter '$id'. Available IDs: capability_report, network_info, evidence_verify, vuln_lookup, apk_static, source_audit, web_passive, tool_catalogue, tool_status, tool_install, tool_run, tool_smoke_test, reliability_self_test, resource_report, audit_verify, task_list, task_create, task_update, result_evaluate, finding_correlate.")
                }
            } catch (e: Exception) {
                fail("$id failed: ${e.message ?: e.javaClass.simpleName}")
            }
        }
        runCatching {
            ReliabilityEngine.appendAudit(context, "security_adapter_execution", JSONObject()
                .put("adapter", id).put("exitCode", result.exitCode)
                .put("outputLength", result.stdout.length).put("errorLength", result.stderr.length))
        }
        if (result.exitCode == 0 && result.stdout.isNotBlank()) {
            runCatching { SecurityIntelligence.saveReport(context, "# Security adapter result: $id\n\n${result.stdout}") }
        }
        return result
    }

    private fun approvedLocalFile(context: Context, path0: String): File {
        require(path0.isNotBlank() && path0.length <= 2048) { "A local file path is required." }
        val file = File(path0).canonicalFile
        val roots = listOf(context.filesDir, context.cacheDir, context.externalCacheDir)
            .filterNotNull().map { it.canonicalFile }
        require(roots.any { root -> file.path.startsWith(root.path + File.separator) || file == root }) {
            "For safety, AI file analysis is limited to files copied into Arin's private files/cache directories. Select or import the file through Arin first."
        }
        require(file.isFile && file.canRead()) { "File does not exist or cannot be read: $path0" }
        require(file.length() in 1..MAX_INPUT_BYTES) { "File is empty or exceeds the 128 MB analysis limit." }
        return file
    }

    private fun toolCommand(id: String): String = when (id) {
        "clamscan" -> "clamscan"
        "wireshark" -> "tshark"
        "testssl" -> "testssl.sh"
        else -> id
    }

    private fun ok(report: String) = Termux.Result(report.take(24_000), "", 0, null)
    private fun fail(message: String) = Termux.Result("", message, 1, null)
}
