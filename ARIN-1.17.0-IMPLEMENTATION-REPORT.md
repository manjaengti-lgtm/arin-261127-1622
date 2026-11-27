# Arin 1.17.0 — Structured AI Security Tool Bridge

## Implemented in source
- Added `SecurityToolBridge`, a structured dispatcher called by the primary chat agent through `<security_tool>{...}</security_tool>`.
- Added parser support in `Prompt.agentAction` and execution in the existing ChatViewModel action/approval loop.
- Every adapter call goes through the existing per-action user approval prompt.
- The bridge does not expose arbitrary shell commands. Linux tool smoke tests use a fixed allowlist and version/help commands only.
- Added adapters: `capability_report`, `network_info`, `evidence_verify`, `vuln_lookup`, `apk_static`, `source_audit`, `web_passive`, `tool_smoke_test`.
- Web and vulnerability database lookups are disabled in offline mode. Web assessment requires both the app approval and `authorised=true` in the structured request.
- File analysis is restricted to readable files inside Arin private files/cache directories, with a 128 MB limit (4 MB for text source).
- Successful adapter outputs are saved to Arin's private security report directory.
- Autopilot now passes the exact path of a user-imported file to the primary AI so it can request the matching static adapter.
- Updated adapter registry and version to 1.17.0 / versionCode 257.

## Important limitations
- This is a real structured tool bridge for the listed built-in adapters, not an unrestricted autonomous pentesting engine.
- Tool smoke tests only prove that an allowlisted command responds to a version/help check; they do not prove that every operational feature works.
- The source inventory remains partial and does not resolve all transitive dependencies.
- Dynamic APK sandboxing, full native decompilation/reconstruction, complete SBOM generation, and a live interactive network topology view remain unimplemented.
- The AI can request one adapter per turn; the primary model must inspect each result before requesting another.
- Runtime behaviour depends on Android permissions, installed tools, network access, and the actual device.

## Verification
- JSON registry parsed successfully.
- Shell scripts passed `bash -n`.
- ZIP integrity checked after packaging.
- Gradle/Kotlin compilation was attempted with `./gradlew --offline :app:compileDebugKotlin --no-daemon`, but the wrapper distribution was not cached and network DNS for `services.gradle.org` was unavailable. Compilation and device runtime are therefore NOT VERIFIED.
