package com.arin.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale
import java.util.zip.ZipInputStream

/**
 * Arin's local security intelligence layer. Adapters describe real capabilities and constraints;
 * unsupported operations are never advertised as working. This registry is intentionally defensive:
 * it exposes static analysis, passive checks, evidence handling and authorised diagnostics only.
 */
object SecurityIntelligence {
    data class Adapter(
        val id: String,
        val title: String,
        val category: String,
        val mode: String,
        val environments: List<String>,
        val command: String? = null,
        val limitation: String = ""
    )

    val adapters = listOf(
        Adapter("apk-static", "APK static analysis", "Reverse engineering", "offline", listOf("Android", "Ubuntu/PRoot"), "ApkAudit", "Deep decompilation requires JADX/Apktool installation."),
        Adapter("source-sbom", "Source and SBOM inspection", "Software supply chain", "offline", listOf("Android"), "SourceAudit", "Dependency versions are extracted from supported manifest/build-file formats; transitive resolution requires a package manager."),
        Adapter("secret-scan", "Secret exposure scan", "Source security", "offline", listOf("Android"), "SourceAudit", "Matches are heuristic and redacted; verify findings manually and rotate exposed credentials."),
        Adapter("web-passive", "Web/API passive assessment", "Web security", "network", listOf("Android"), "WebAudit", "Uses ordinary HTTP requests; no fuzzing, exploitation or credential testing."),
        Adapter("network-info", "Local network configuration", "Network security", "offline", listOf("Android"), "NetAudit", "Android limits raw packet capture and monitor mode without supported privileged hardware."),
        Adapter("host-check", "Authorised host service check", "Network security", "network", listOf("Android", "Ubuntu/PRoot"), "NetAudit", "Ordinary TCP connection checks only; use only on systems you own or are authorised to assess."),
        Adapter("evidence", "Evidence hashing and custody", "Digital forensics", "offline", listOf("Android"), "Forensics", "Preserves a private copy and records hashes; it does not establish legal admissibility."),
        Adapter("vuln-intel", "CVE and KEV correlation", "Vulnerability intelligence", "network", listOf("Android"), "VulnIntel", "Product/version matches are leads, not proof of vulnerability; backports may change applicability."),
        Adapter("toolkit", "Linux defensive tool adapters", "Tool management", "linux", listOf("Ubuntu/PRoot", "Remote Linux"), "Linux", "Each tool needs a successful runtime smoke test; PRoot is not Android root."),
        Adapter("forensic-timeline", "Evidence activity timeline", "Digital forensics", "offline", listOf("Android"), "Forensics", "Timeline uses timestamps recorded by Arin and source metadata when available."),
        Adapter("reliability", "Local reliability self-tests", "Reliability", "offline", listOf("Android"), "ReliabilityEngine", "Tests local storage, JSON and hash primitives; not app compilation or live provider connectivity."),
        Adapter("task-ledger", "Persistent investigation task ledger", "Orchestration", "offline", listOf("Android"), "ReliabilityEngine", "Persists task status and notes locally; tasks do not run themselves."),
        Adapter("audit-chain", "Hash-chained execution audit", "Governance", "offline", listOf("Android"), "ReliabilityEngine", "Detects edits/deletions in the current log; app-private storage is not tamper-proof against a privileged attacker."),
        Adapter("resource-report", "Device resource snapshot", "Reliability", "offline", listOf("Android"), "ReliabilityEngine", "Point-in-time RAM and storage estimate; not a workload guarantee.")
    )

    fun modelCapabilityNote(context: Context? = null): String = buildString {
        appendLine("ARIN SECURITY CAPABILITY REGISTRY (ground truth; never claim unverified tools are installed):")
        adapters.forEach { a ->
            appendLine("- ${a.id}: ${a.title}; category=${a.category}; mode=${a.mode}; environments=${a.environments.joinToString()}; adapter=${a.command ?: "built-in"}; limitation=${a.limitation}")
        }
        if (context != null) {
            val linuxReady = runCatching { com.arin.terminal.Linux.installed(context) }.getOrDefault(false)
            val javaReady = runCatching { com.arin.terminal.Linux.toolInstalled(context, com.arin.terminal.Linux.Tool.JAVA) }.getOrDefault(false)
            val sdkReady = runCatching { com.arin.terminal.Linux.toolInstalled(context, com.arin.terminal.Linux.Tool.ANDROID_SDK) }.getOrDefault(false)
            val apkReady = runCatching { com.arin.terminal.Linux.toolInstalled(context, com.arin.terminal.Linux.Tool.APK_TOOLKIT) }.getOrDefault(false)
            appendLine("LIVE ENVIRONMENT MARKERS (installation markers only; not proof of command execution):")
            appendLine("- Built-in Linux/PRoot installed marker: $linuxReady")
            appendLine("- Java/Kotlin/Gradle installed marker: $javaReady")
            appendLine("- Android SDK/build-tools installed marker: $sdkReady")
            appendLine("- APK toolkit installed marker: $apkReady")
            appendLine("Do not describe these markers as successful runtime smoke tests. Verify the actual command/version before relying on a tool.")
        }
        appendLine("CATALOGUE TOOL PIPELINE (fixed adapter allowlist):")
        ToolPipeline.tools.forEach { t -> appendLine("- ${t.id}: binary=${t.binary}; category=${t.category}; environment=${t.environment}; mode=${t.mode}; limitation=${t.limitation}") }
        appendLine("AI tool bridge: capability_report, network_info, evidence_verify, vuln_lookup, apk_static, source_audit, web_passive, tool_catalogue, tool_status, tool_install, tool_run, tool_smoke_test, reliability_self_test, resource_report, audit_verify, task_list, task_create, task_update, result_evaluate, finding_correlate. Each invocation requires user approval; network checks require explicit owner/authorisation confirmation. Do not execute destructive, stealth, credential-theft or unauthorised operations. Report evidence, confidence, limitations and remediation separately.")
    }

    fun offlineMode(context: Context): Boolean = context.getSharedPreferences("security-intelligence", Context.MODE_PRIVATE).getBoolean("offline_mode", false)
    fun setOfflineMode(context: Context, enabled: Boolean) {
        context.getSharedPreferences("security-intelligence", Context.MODE_PRIVATE).edit().putBoolean("offline_mode", enabled).apply()
    }

    fun saveReport(context: Context, report: String): File {
        val dir = File(context.filesDir, "security/reports").apply { mkdirs() }
        return File(dir, "arin-security-${System.currentTimeMillis()}.md").apply { writeText(report) }
    }
}

/** Bounded local source/archive inspection. No archive extraction and no network access. */
object SourceAudit {
    private const val MAX_ENTRIES = 5000
    private const val MAX_TOTAL_BYTES = 32L * 1024 * 1024
    private const val MAX_ENTRY_BYTES = 2 * 1024 * 1024
    private const val MAX_TOTAL_ARCHIVE_BYTES = 128L * 1024 * 1024

    private val secretPatterns = listOf(
        "Possible private key" to Regex("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Possible AWS access key" to Regex("\\bAKIA[0-9A-Z]{16}\\b"),
        "Possible GitHub token" to Regex("\\bgh[pousr]_[A-Za-z0-9]{20,}\\b"),
        "Possible generic API key" to Regex("(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret)\\s*[:=]\\s*['\"]?[A-Za-z0-9_./+=-]{16,}"),
        "Possible password assignment" to Regex("(?i)(?:password|passwd)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]")
    )

    fun analyseText(name: String, text: String): String {
        val deps = linkedSetOf<String>()
        val gradle = Regex("(?:implementation|api|runtimeOnly|testImplementation|classpath)\\s*\\(?\\s*[\"']([^\"']+:[^\"']+:[^\"']+)[\"']")
        gradle.findAll(text).take(300).forEach { deps += it.groupValues[1] }
        val maven = Regex("<groupId>([^<]+)</groupId>\\s*<artifactId>([^<]+)</artifactId>\\s*<version>([^<]+)</version>", RegexOption.DOT_MATCHES_ALL)
        maven.findAll(text).take(300).forEach { deps += "${it.groupValues[1]}:${it.groupValues[2]}:${it.groupValues[3]}" }
        val npm = Regex("""["']([^"']+)["']\s*:\s*["']([~^]?[0-9][^"']*)["']""")
        if (text.contains("\"dependencies\"") || text.contains("\"devDependencies\"")) {
            npm.findAll(text).take(300).forEach { deps += "npm:${it.groupValues[1]}:${it.groupValues[2]}" }
        }
        val requirements = Regex("(?m)^\\s*([A-Za-z0-9_.-]+)\\s*(?:==|>=|~=)\\s*([A-Za-z0-9_.+-]+)")
        requirements.findAll(text).take(300).forEach { deps += "pypi:${it.groupValues[1]}:${it.groupValues[2]}" }
        val secrets = secretPatterns.flatMap { (label, rx) -> rx.findAll(text).take(15).map { label to redact(it.value) }.toList() }
        return buildString {
            appendLine("# Source security and dependency report — $name")
            appendLine("_Offline heuristic analysis · ${java.util.Date()}_")
            appendLine("\n## Dependency inventory (SBOM seed)")
            if (deps.isEmpty()) appendLine("No supported explicit dependency coordinates were recognised.")
            else deps.forEach { appendLine("- `$it`") }
            appendLine("\n## CycloneDX-style component JSON (partial inventory)")
            val components = JSONArray()
            deps.forEach { d ->
                val p = d.split(':')
                if (p.size >= 3) components.put(JSONObject().put("type", "library").put("group", p[0]).put("name", p[1]).put("version", p[2]))
            }
            appendLine(JSONObject().put("bomFormat", "CycloneDX").put("specVersion", "1.5").put("version", 1).put("components", components).toString(2))
            appendLine("\n## Possible exposed secrets (redacted)")
            if (secrets.isEmpty()) appendLine("No matches from the built-in heuristic patterns.")
            else secrets.distinct().forEach { (label, value) -> appendLine("- **$label** — `$value`") }
            appendLine("\n## Analysis limitations")
            appendLine("- This is a partial, static inventory; it does not resolve transitive dependencies or query vulnerability databases.")
            appendLine("- Secret patterns can produce false positives and miss encoded or dynamically assembled secrets.")
            appendLine("- No code was executed and no files were modified.")
            appendLine("\n## Recommended next steps")
            appendLine("- Resolve dependencies with the project's own package manager and generate a complete SBOM.")
            appendLine("- Validate any secret finding; revoke and rotate real exposed credentials.")
            appendLine("- Run a maintained SCA/SAST scanner and review its version-specific advisories.")
        }
    }

    fun analyseArchive(file: File, onStep: (String) -> Unit = {}): String {
        val names = mutableListOf<String>()
        val texts = StringBuilder()
        var entries = 0
        var total = 0L
        var dex = 0; var native = 0; var manifests = 0; var gradleFiles = 0
        val errors = mutableListOf<String>()
        ZipInputStream(file.inputStream().buffered()).use { zip ->
            while (true) {
                val e = zip.nextEntry ?: break
                entries++
                if (entries > MAX_ENTRIES) { errors += "Entry limit reached ($MAX_ENTRIES)."; break }
                val name = e.name.replace('\\', '/')
                if (name.startsWith("/") || name.split('/').any { it == ".." }) { errors += "Unsafe archive path ignored: ${name.take(120)}"; continue }
                names += name.take(240)
                if (name.endsWith("classes.dex")) dex++
                if (name.endsWith(".so")) native++
                if (name.endsWith("AndroidManifest.xml")) manifests++
                if (name.endsWith("build.gradle") || name.endsWith("build.gradle.kts") || name.endsWith("pom.xml") || name.endsWith("package.json")) gradleFiles++
                val isText = name.endsWith(".gradle") || name.endsWith(".gradle.kts") || name.endsWith("pom.xml") || name.endsWith("package.json") || name.endsWith("requirements.txt") || name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".json")
                if (!e.isDirectory) {
                    // Count decompressed bytes for EVERY entry, not only text files. Otherwise a ZIP bomb
                    // hidden in a binary entry could be drained by closeEntry()/nextEntry without a bound.
                    val out = if (isText) java.io.ByteArrayOutputStream() else null
                    val buf = ByteArray(8192)
                    var entryBytes = 0L
                    var archiveLimitReached = false
                    while (true) {
                        val n = zip.read(buf)
                        if (n < 0) break
                        entryBytes += n
                        total += n
                        if (total > MAX_TOTAL_ARCHIVE_BYTES) {
                            errors += "Total decompressed archive limit reached ($MAX_TOTAL_ARCHIVE_BYTES bytes); remaining entries were not read."
                            archiveLimitReached = true
                            break
                        }
                        if (isText) {
                            if (entryBytes > MAX_ENTRY_BYTES || total > MAX_TOTAL_BYTES) {
                                errors += "Text scan byte limit reached; remaining text files skipped."
                                archiveLimitReached = true
                                break
                            }
                            out?.write(buf, 0, n)
                        }
                    }
                    if (isText && !archiveLimitReached && entryBytes <= MAX_ENTRY_BYTES && total <= MAX_TOTAL_BYTES) {
                        texts.append("\n// FILE: ").append(name).append('\n').append(out?.toString(Charsets.UTF_8.name())?.take(150_000).orEmpty())
                    }
                    if (archiveLimitReached) break
                }
                zip.closeEntry()
                if (entries % 250 == 0) onStep("Inspected $entries archive entries")
            }
        }
        val sourceReport = analyseText(file.name, texts.toString())
        return buildString {
            appendLine("# Archive investigation — ${file.name}")
            appendLine("- Archive size: ${file.length()} bytes")
            appendLine("- Entries inspected: $entries")
            appendLine("- DEX files: $dex · native libraries: $native · Android manifests: $manifests · build/dependency manifests: $gradleFiles")
            appendLine("\n## Sample archive paths")
            names.take(120).forEach { appendLine("- `$it`") }
            if (names.size > 120) appendLine("- … ${names.size - 120} more paths omitted")
            if (errors.isNotEmpty()) { appendLine("\n## Limits / warnings"); errors.distinct().forEach { appendLine("- $it") } }
            appendLine("\n## Source/dependency analysis")
            appendLine(sourceReport)
            appendLine("\n_Archive was inspected in memory; entries were not extracted or executed._")
        }
    }

    private fun redact(value: String): String {
        if (value.length <= 10) return "[REDACTED]"
        return value.take(4) + "…[REDACTED]…" + value.takeLast(3)
    }
}
