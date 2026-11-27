package com.arin.security

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.StatFs
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** Local reliability primitives: durable task ledger, hash-chained audit trail, resource snapshot,
 * adapter self-tests and conservative result evaluation. No network access or shell execution. */
object ReliabilityEngine {
    private const val MAX_TASKS = 500
    private const val MAX_AUDIT_BYTES = 8L * 1024 * 1024
    private const val GENESIS = "ARIN-AUDIT-GENESIS-v1"

    private fun root(context: Context) = File(context.filesDir, "security/reliability").apply { mkdirs() }
    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    @Synchronized fun createTask(context: Context, title: String, objective: String = ""): String {
        require(title.isNotBlank() && title.length <= 180) { "Task title must be 1–180 characters." }
        val tasks = readTasks(context)
        require(tasks.length() < MAX_TASKS) { "Task ledger limit reached. Archive old tasks first." }
        val id = UUID.randomUUID().toString()
        val now = System.currentTimeMillis()
        val task = JSONObject().put("id", id).put("title", title.trim())
            .put("objective", objective.take(2000)).put("status", "PENDING")
            .put("createdAt", now).put("updatedAt", now).put("steps", JSONArray())
        tasks.put(task)
        writeTasks(context, tasks)
        appendAudit(context, "task_created", JSONObject().put("taskId", id).put("title", title.take(180)))
        return id
    }

    @Synchronized fun updateTask(context: Context, id: String, status: String, note: String = ""): String {
        val allowed = setOf("PENDING", "IN_PROGRESS", "BLOCKED", "TESTING", "COMPLETED", "VERIFIED", "FAILED")
        require(status in allowed) { "Unsupported task status." }
        require(note.length <= 3000) { "Task note is too long." }
        val tasks = readTasks(context)
        var found: JSONObject? = null
        for (i in 0 until tasks.length()) {
            val item = tasks.optJSONObject(i) ?: continue
            if (item.optString("id") == id) { found = item; break }
        }
        val task = found ?: throw IllegalArgumentException("Task not found.")
        task.put("status", status).put("updatedAt", System.currentTimeMillis())
        if (note.isNotBlank()) task.optJSONArray("steps")?.put(JSONObject().put("at", System.currentTimeMillis()).put("note", note))
        writeTasks(context, tasks)
        appendAudit(context, "task_updated", JSONObject().put("taskId", id).put("status", status))
        return task.toString(2)
    }

    fun taskReport(context: Context): String {
        val tasks = readTasks(context)
        return buildString {
            appendLine("# Arin persistent task ledger")
            appendLine("Tasks: ${tasks.length()}")
            for (i in 0 until tasks.length()) {
                val t = tasks.optJSONObject(i) ?: continue
                appendLine("\n## ${t.optString("title")} [${t.optString("status")}]")
                appendLine("- ID: `${t.optString("id")}`")
                appendLine("- Created: ${t.optLong("createdAt")}")
                appendLine("- Objective: ${t.optString("objective")}")
                val steps = t.optJSONArray("steps") ?: JSONArray()
                for (j in 0 until steps.length()) appendLine("  - ${steps.optJSONObject(j)?.optString("note") ?: ""}")
            }
        }
    }

    @Synchronized fun appendAudit(context: Context, event: String, details: JSONObject = JSONObject()) {
        require(event.matches(Regex("[a-z0-9_]{1,64}"))) { "Invalid audit event." }
        val file = File(root(context), "audit.jsonl")
        if (file.exists() && file.length() > MAX_AUDIT_BYTES) throw IllegalStateException("Audit log reached 8 MB; export and archive it before continuing.")
        val previous = if (file.exists() && file.length() > 0) runCatching {
            file.useLines { lines -> lines.lastOrNull()?.let { JSONObject(it).optString("hash") } }
        }.getOrNull().orEmpty() else GENESIS
        val safe = JSONObject()
        val keys = details.keys()
        while (keys.hasNext()) {
val key = keys.next()
            if (key.matches(Regex("[A-Za-z0-9_.-]{1,48}"))) {
                val value = details.opt(key)
                if (value is String || value is Number || value is Boolean || value == JSONObject.NULL) safe.put(key, value.toString().take(240))
            }
        }
        val eventBody = JSONObject().put("at", System.currentTimeMillis()).put("event", event).put("details", safe).put("previousHash", previous)
        eventBody.put("hash", sha256(eventBody.toString()))
        file.parentFile?.mkdirs()
        file.appendText(eventBody.toString() + "\n")
    }

    fun verifyAudit(context: Context): String {
        val file = File(root(context), "audit.jsonl")
        if (!file.exists()) return "No audit events recorded yet."
        if (file.length() > MAX_AUDIT_BYTES) return "Audit log exceeds verification size limit."
        var previous = GENESIS
        var count = 0
        for (line in file.readLines()) {
            if (line.isBlank()) continue
            val obj = runCatching { JSONObject(line) }.getOrElse { return "FAILED: malformed record at line ${count + 1}." }
            val recorded = obj.optString("hash")
            val base = JSONObject().put("at", obj.optLong("at")).put("event", obj.optString("event"))
                .put("details", obj.optJSONObject("details") ?: JSONObject())
                .put("previousHash", obj.optString("previousHash"))
            if (obj.optString("previousHash") != previous || sha256(base.toString()) != recorded)
                return "FAILED: audit-chain mismatch at line ${count + 1}."
            previous = recorded
            count++
        }
        return "PASSED: $count audit records form an intact hash chain. This detects edits/deletions within the current log, but does not protect against an attacker who can replace the entire app-private log and its history."
    }

    fun resourceReport(context: Context): String {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mem = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
        val stat = StatFs(context.filesDir.absolutePath)
        val free = stat.availableBytes
        return buildString {
            appendLine("# Device resource snapshot")
            appendLine("- Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
            appendLine("- ABIs: ${Build.SUPPORTED_ABIS.joinToString()}")
            appendLine("- RAM available: ${mem.availMem / (1024 * 1024)} MB")
            appendLine("- Low-memory state: ${mem.lowMemory}")
            appendLine("- App-filesystem available: ${free / (1024 * 1024)} MB")
            appendLine("- Threshold: ${mem.threshold / (1024 * 1024)} MB")
            appendLine("This is a point-in-time estimate; it is not a guarantee that a workload will fit.")
        }
    }

    fun selfTest(context: Context): String {
        val checks = mutableListOf<Pair<String, Boolean>>()
        checks += "Private storage writable" to runCatching { File(root(context), "selftest.tmp").writeText("ok"); File(root(context), "selftest.tmp").delete(); true }.getOrDefault(false)
        checks += "Task ledger readable" to runCatching { readTasks(context); true }.getOrDefault(false)
        checks += "Audit hash function" to runCatching { sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }.getOrDefault(false)
        checks += "JSON parser" to runCatching { JSONObject("{\"ok\":true}").getBoolean("ok") }.getOrDefault(false)
        checks += "Offline preference readable" to runCatching { SecurityIntelligence.offlineMode(context); true }.getOrDefault(false)
        checks += "Audit chain append/verify" to runCatching {
            appendAudit(context, "self_test_probe", JSONObject().put("probe", true))
            verifyAudit(context).startsWith("PASSED:")
        }.getOrDefault(false)
        val passed = checks.count { it.second }
        appendAudit(context, "reliability_self_test", JSONObject().put("passed", passed).put("total", checks.size))
        return buildString {
            appendLine("# Arin reliability self-test")
            checks.forEach { appendLine("- ${if (it.second) "PASS" else "FAIL"}: ${it.first}") }
            appendLine("\nResult: $passed/${checks.size} checks passed.")
            appendLine("These checks validate local primitives only; they do not prove that Android compilation, AI provider connectivity or third-party tools work.")
        }
    }

    fun evaluateResult(exitCode: Int, stdout: String, stderr: String): String {
        val hasOutput = stdout.isNotBlank()
        val hasError = stderr.isNotBlank()
        val status = when { exitCode != 0 -> "FAILED"; !hasOutput -> "INCONCLUSIVE"; else -> "EXECUTED_WITH_OUTPUT" }
        return """# Execution result evaluation
Status: $status
Exit code: $exitCode
Standard output present: $hasOutput
Standard error present: $hasError
Output length: ${stdout.length} characters
Error length: ${stderr.length} characters

Interpretation: A zero exit code and output indicate that a process returned output; they do not prove the finding is correct or that the intended security objective was achieved. Review evidence, tool version, scope and limitations independently."""
    }

    fun correlateFindings(findings: JSONArray): String {
        require(findings.length() <= 500) { "At most 500 findings can be correlated at once." }
        val seen = linkedSetOf<String>()
        val unique = mutableListOf<JSONObject>()
        var duplicates = 0
        for (i in 0 until findings.length()) {
            val item = findings.optJSONObject(i) ?: continue
            val title = item.optString("title").trim().take(200)
            val artifact = item.optString("artifact").trim().take(300)
            if (title.isBlank()) continue
            val key = (title.lowercase() + "|" + artifact.lowercase())
            if (seen.add(key)) unique += JSONObject().put("title", title).put("artifact", artifact)
            else duplicates++
        }
        return buildString {
            appendLine("# Finding correlation")
            appendLine("Input: ${findings.length()} · unique title/artifact pairs: ${unique.size} · duplicates: $duplicates")
            unique.forEach { appendLine("- ${it.optString("title")}" + it.optString("artifact").takeIf(String::isNotBlank)?.let { a -> " — $a" }.orEmpty()) }
            appendLine("\nCorrelation is exact-match deduplication only; it does not establish causality or confirm vulnerability validity.")
        }
    }

    private fun readTasks(context: Context): JSONArray {
        val file = File(root(context), "tasks.json")
        return if (!file.exists()) JSONArray() else JSONArray(file.readText())
    }
    private fun writeTasks(context: Context, tasks: JSONArray) {
        val file = File(root(context), "tasks.json")
        val tmp = File(file.parentFile, "tasks.json.tmp")
        tmp.writeText(tasks.toString())
        if (file.exists() && !file.delete()) throw IllegalStateException("Could not replace task ledger.")
        if (!tmp.renameTo(file)) throw IllegalStateException("Could not commit task ledger.")
    }
}
