package com.arin.security

import android.content.Context
import com.arin.terminal.AgentTools
import com.arin.terminal.Linux
import com.arin.terminal.Shell
import com.arin.terminal.Termux
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Registry-backed execution pipeline for Arin's defensive security catalogue.
 * Tool names are resolved through a fixed allowlist; the model never supplies shell syntax.
 * Every call is made only after the existing user-approval gate in ChatViewModel.
 */
object ToolPipeline {
    data class Tool(
        val id: String, val binary: String, val category: String, val environment: String,
        val installSpec: String? = null, val mode: String = "offline", val limitation: String = ""
    )

    val tools = listOf(
        Tool("jadx", "jadx", "APK reverse engineering", "Ubuntu/PRoot or remote Linux", mode="offline", limitation="Requires the APK toolkit and Java."),
        Tool("apktool", "apktool", "APK resource analysis", "Ubuntu/PRoot or remote Linux", mode="offline", limitation="Rebuilding requires compatible Android build tools and signing."),
        Tool("androguard", "androguard", "APK/DEX analysis", "Ubuntu/PRoot or remote Linux", mode="offline", limitation="Python package and CLI version must be verified."),
        Tool("nmap", "nmap", "Authorised host diagnostics", "Termux/PRoot/remote Linux", "apt:nmap", "network", "Only bounded TCP connect discovery on explicitly authorised targets."),
        Tool("tshark", "tshark", "Offline packet analysis", "Ubuntu/PRoot or remote Linux", "apt:tshark"),
        Tool("wireshark-cli", "tshark", "Offline packet analysis", "Ubuntu/PRoot or remote Linux", "apt:wireshark-common"),
        Tool("yara", "yara", "File pattern triage", "Ubuntu/PRoot or remote Linux", "apt:yara"),
        Tool("clamav", "clamscan", "Signature-based malware triage", "Ubuntu/PRoot or remote Linux", "apt:clamav", limitation="Update signatures with freshclam; detection is not guaranteed."),
        Tool("binwalk", "binwalk", "Firmware/file structure inspection", "Ubuntu/PRoot or remote Linux", "apt:binwalk"),
        Tool("sleuthkit", "mmls", "Forensic filesystem inspection", "Ubuntu/PRoot or remote Linux", "apt:sleuthkit", limitation="Requires a forensic image; does not establish legal admissibility."),
        Tool("sqlite3", "sqlite3", "Read-only database inspection", "Termux/PRoot/remote Linux", "apt:sqlite3"),
        Tool("semgrep", "semgrep", "Source code security analysis", "Ubuntu/PRoot or remote Linux", "pipx:semgrep"),
        Tool("bandit", "bandit", "Python security linting", "Ubuntu/PRoot or remote Linux", "pipx:bandit"),
        Tool("shellcheck", "shellcheck", "Shell static analysis", "Termux/PRoot/remote Linux", "apt:shellcheck"),
        Tool("trivy", "trivy", "Dependency and filesystem scanning", "Ubuntu/PRoot or remote Linux", mode="offline", limitation="Binary must be installed from the official vendor source; vulnerability DB refresh needs internet."),
        Tool("testssl", "testssl.sh", "TLS configuration assessment", "Ubuntu/PRoot or remote Linux", mode="network", limitation="Requires explicit authorisation and online mode."),
        Tool("owasp-zap", "zap.sh", "Web application assessment", "Remote/desktop Linux", mode="remote", limitation="Not advertised as locally executable on Android/PRoot; use a separately configured remote lab."),
        Tool("kismet", "kismet", "Wireless diagnostics", "Compatible Linux hardware", mode="hardware", limitation="Requires supported wireless chipset/driver and privileges; Android PRoot cannot provide monitor mode."),
    )

    fun catalogueReport(context: Context): String = buildString {
        appendLine("# Arin tool pipeline status")
        appendLine("Environment: ${if (Shell.usesLinux(context)) "Arin Ubuntu/PRoot" else if (Shell.problem(context) == null) "Termux" else "No terminal connected"}")
        tools.forEach { t ->
            val status = if (t.mode in setOf("remote", "hardware")) "NOT_LOCAL" else "NOT_TESTED"
            appendLine("- ${t.id} (${t.binary}): $status; category=${t.category}; environment=${t.environment}; mode=${t.mode}; ${t.limitation}")
        }
        appendLine("NOT_TESTED means no successful runtime check has been recorded. This report does not claim installation or functionality.")
    }

    suspend fun status(context: Context): Termux.Result = withContext(Dispatchers.IO) {
        if (!Shell.usesLinux(context)) return@withContext Termux.Result(catalogueReport(context) + "\nInstall Arin Ubuntu/PRoot to run this catalogue locally; Termux command presence is not treated as pipeline readiness.", "", 0, null)
        val lines = StringBuilder("# Runtime tool verification\n")
        var working = 0
        tools.forEach { t ->
            if (t.mode in setOf("remote", "hardware")) {
                lines.appendLine("${t.id}: NOT_LOCAL — ${t.limitation}")
            } else {
                val q = quote(t.binary)
                val r = Shell.run(context, "export PATH=\"\$HOME/.local/bin:/opt/pipx/bin:\$HOME/bin:\$PATH\"; if command -v $q >/dev/null 2>&1; then command -v $q; $q --version >/tmp/arin-tool-check.out 2>&1; rc=\$?; if [ \$rc -ne 0 ]; then $q --help >/tmp/arin-tool-check.out 2>&1; rc=\$?; fi; head -3 /tmp/arin-tool-check.out; exit \$rc; else echo MISSING; exit 127; fi", 20_000L)
                if (r.exitCode == 0 && !r.stdout.contains("MISSING")) working++
                lines.appendLine("${t.id}: ${if (r.exitCode == 0) "COMMAND_RESPONDED" else "MISSING_OR_FAILED"}\n${(r.stdout + "\n" + r.stderr).trim().take(700)}")
            }
        }
        lines.appendLine("\nCommands responding: $working/${tools.size - 2}. A version/help response is a smoke test, not proof that all analysis functions work.")
        Termux.Result(lines.toString().take(22_000), "", 0, null)
    }

    suspend fun install(context: Context, id: String): Termux.Result {
        val t = tools.firstOrNull { it.id == id.lowercase() }
            ?: return Termux.Result("", "Tool is not in Arin's signed-in-app catalogue: $id", 1, null)
        if (!Shell.usesLinux(context)) return Termux.Result("", "Install Arin's Ubuntu/PRoot environment before installing tools into the app's execution pipeline.", 2, null)
        if (t.mode == "remote" || t.mode == "hardware")
            return Termux.Result("", "${t.id} cannot be installed as a working local Android/PRoot tool. ${t.limitation}", 2, null)
        if (t.id in setOf("jadx", "apktool", "androguard")) {
            if (!Shell.usesLinux(context)) return Termux.Result("", "Install Arin's Ubuntu/PRoot environment first. The APK toolkit installer is Linux-based.", 2, null)
            return com.arin.terminal.Linux.installApkToolkit(context) { }
        }
        if (t.id == "trivy") return Termux.Result("", "Trivy requires its official vendor installation for this architecture. Arin will not download an unverified binary. Install from https://aquasecurity.github.io/trivy/ and run tool_status to verify.", 2, null)
        if (t.id == "testssl") return Termux.Result("", "Install testssl.sh from its official repository in Arin's Linux environment, then run tool_status. Automatic clone/install is not enabled in this build.", 2, null)
        val spec = t.installSpec ?: return Termux.Result("", "No verified installer is configured for ${t.id}.", 2, null)
        return AgentTools.install(context, spec)
    }

    suspend fun run(context: Context, id: String, args: org.json.JSONObject): Termux.Result {
        val t = tools.firstOrNull { it.id == id.lowercase() }
            ?: return Termux.Result("", "Unknown tool id: $id", 1, null)
        if (t.mode in setOf("remote", "hardware")) return Termux.Result("", "${t.id} is not executable in this local environment. ${t.limitation}", 2, null)
        if (!Shell.usesLinux(context)) return Termux.Result("", "This adapter requires Arin's Ubuntu/PRoot environment. Termux/Android private file paths are not exposed to this isolated Linux tool runner. Install Arin Linux, then retry.", 2, null)
        if (t.mode == "network") {
            if (SecurityIntelligence.offlineMode(context)) return Termux.Result("", "Offline mode blocks network tools.", 2, null)
            if (!args.optBoolean("authorised", false)) return Termux.Result("", "Explicit owner/authorised-scope confirmation is required.", 2, null)
        }
        val path = args.optString("path").trim().takeIf { it.isNotBlank() }?.let { approvedLinuxPath(context, it) }
        val rules = args.optString("rules").trim().takeIf { it.isNotBlank() }?.let { approvedLinuxPath(context, it) }
        val ext = path?.substringAfterLast('.', "")?.lowercase().orEmpty()
        val command = when (t.id) {
            "jadx" -> { require(path != null && ext == "apk") { "Attach/import an APK into /root/files and provide its Linux path." }; "mkdir -p /root/files/arin-tool-output && jadx -d ${quote("/root/files/arin-tool-output/jadx-${System.currentTimeMillis()}")} ${quote(path)}" }
            "apktool" -> { require(path != null && ext == "apk") { "Attach/import an APK into /root/files and provide its Linux path." }; "mkdir -p /root/files/arin-tool-output && apktool d -f ${quote(path)} -o ${quote("/root/files/arin-tool-output/apktool-${System.currentTimeMillis()}")}" }
            "androguard" -> { require(path != null && ext == "apk") { "Attach/import an APK into /root/files and provide its Linux path." }; "androguard analyze ${quote(path)}" }
            "tshark", "wireshark-cli" -> { require(path != null && ext in setOf("pcap", "pcapng", "cap")) { "Provide an imported PCAP/PCAPNG path under /root/files." }; "tshark -r ${quote(path)} -q -z io,phs" }
            "yara" -> { require(path != null && rules != null) { "Provide sample path and YARA rules path under /root/files." }; "yara -r ${quote(rules)} ${quote(path)}" }
            "clamav" -> { require(path != null) { "Provide an imported file path under /root/files." }; "clamscan --no-summary ${quote(path)}" }
            "binwalk" -> { require(path != null) { "Provide an imported firmware/file image path under /root/files." }; "binwalk ${quote(path)}" }
            "sleuthkit" -> { require(path != null) { "Provide an imported forensic disk image path under /root/files." }; "mmls ${quote(path)}" }
            "sqlite3" -> { require(path != null && ext in setOf("db", "sqlite", "sqlite3")) { "Provide an imported SQLite database path (.db/.sqlite/.sqlite3)." }; val sql = args.optString("query", "SELECT name, type FROM sqlite_master LIMIT 100;").trim(); require(sql.length <= 2000 && !sql.dropLastWhile { it == ';' || it.isWhitespace() }.contains(';') && Regex("(?is)^\\s*(SELECT|PRAGMA\\s+table_info)\\b").containsMatchIn(sql) && !Regex("(?i)\\b(INSERT|UPDATE|DELETE|DROP|ALTER|ATTACH|DETACH|VACUUM)\\b").containsMatchIn(sql)) { "Only one bounded read-only SELECT or table_info PRAGMA query is allowed." }; "sqlite3 -readonly ${quote(path)} ${quote(sql)}" }
            "semgrep" -> { require(path != null && rules != null) { "Provide imported source path and local Semgrep rules path under /root/files. Local rules keep the scan offline." }; "semgrep scan --config ${quote(rules)} --no-git-ignore ${quote(path)}" }
            "bandit" -> { require(path != null) { "Provide an imported Python file or source directory path under /root/files." }; "bandit -r ${quote(path)} -f txt" }
            "shellcheck" -> { require(path != null && ext in setOf("sh", "bash")) { "Provide an imported shell script path under /root/files." }; "shellcheck ${quote(path)}" }
            "trivy" -> { require(path != null) { "Provide an imported source directory or artifact path under /root/files." }; "trivy fs --skip-db-update --skip-java-db-update --scanners vuln,misconfig,secret --skip-dirs .git ${quote(path)}" }
            "nmap" -> { val host = args.optString("target").trim(); require(host.matches(Regex("(?i)^[a-z0-9.-]{1,253}$")) && !host.startsWith("-") && !host.contains("..")) { "Provide a single valid hostname/IP (no CIDR or ranges)." }; "nmap -sT -sV --top-ports 100 --host-timeout 60s --max-retries 1 ${quote(host)}" }
            "testssl" -> { val host = args.optString("target").trim(); require(host.matches(Regex("(?i)^[a-z0-9.-]{1,253}$")) && !host.startsWith("-")) { "Provide a single hostname only." }; "testssl.sh --fast --warnings off ${quote(host)}" }
            else -> return Termux.Result("", "No executable operation is configured for ${t.id}.", 2, null)
        }
        return Shell.run(context, "export PATH=\"\$HOME/.local/bin:/opt/pipx/bin:\$HOME/bin:\$PATH\"; $command", if (t.id in setOf("semgrep", "trivy", "jadx", "apktool")) 10 * 60_000L else 3 * 60_000L)
    }

    /** External Linux tools can only see imported files under /root/files in Arin's PRoot rootfs. */
    private fun approvedLinuxPath(context: Context, raw: String): String {
        require(raw.startsWith("${Linux.FILES}/") && raw.length <= 2048) { "Tool inputs must be imported through Arin and referenced by their /root/files/... Linux path." }
        val root = File(Linux.rootfs(context), "root/files").canonicalFile
        val physical = File(Linux.rootfs(context), raw.removePrefix("/")).canonicalFile
        require(physical.path.startsWith(root.path + File.separator)) { "Input path escapes Arin's imported-files directory." }
        require(physical.exists() && (physical.isFile || physical.isDirectory)) { "Imported input does not exist: $raw" }
        if (physical.isFile) require(physical.length() in 1..128L * 1024 * 1024) { "Input must be between 1 byte and 128 MB." }
        else {
            var count = 0
            var total = 0L
            physical.walkTopDown().forEach { child ->
                if (child.isFile) { count++; total += child.length() }
                require(count <= 5000 && total <= 128L * 1024 * 1024) { "Directory input exceeds 5,000 files or 128 MB." }
            }
        }
        return raw
    }

    private fun quote(s: String): String = "'" + s.replace("'", "'\\''") + "'"
}
