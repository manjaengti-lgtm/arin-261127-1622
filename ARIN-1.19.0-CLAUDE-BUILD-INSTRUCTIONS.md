# Arin 1.19.0 — build and validate the complete tool pipeline

Use this source tree as the new baseline. Do not use an older Arin ZIP.

1. Inspect `ToolPipeline.kt`, `SecurityToolBridge.kt`, `SecurityIntelligence.kt`, `ToolkitScreen.kt`, `AgentTools.kt`, and the `ChatViewModel.kt` structured security prompt.
2. Preserve `PROTECTED_RULES.md`, existing app features, package ID and signing configuration. Do not modify `ContentGate.kt` if present.
3. Compile with the project's Gradle wrapper and resolve all Kotlin/Gradle/dependency errors in grouped root-cause passes.
4. Verify the structured path from model `<security_tool>` response → parser → approval prompt → bridge → adapter → actual stdout/stderr/exit code → audit log/report → model continuation.
5. Test all 18 registry entries. For locally supported tools, install, verify version/help, then run a safe fixture test. For Nmap/testssl, use only a loopback or explicitly owned lab target after approval. Do not probe third-party systems.
6. Verify ZAP is reported as remote-only and Kismet as hardware-dependent; do not show either as locally working without a real supported environment.
7. Test imported `/root/files` path enforcement, traversal/symlink rejection, size and directory limits, offline mode, malformed payloads, missing commands, timeout handling, and user denial.
8. Verify pipx-installed binaries are discoverable in new non-interactive tool sessions.
9. Run unit tests, lint, APK assembly and install/runtime tests if an emulator/device is available.
10. Return the APK, full build log, test matrix, exact runtime status for each tool, and all unresolved limitations. Never mark a tool WORKING merely because its catalogue entry exists.

No arbitrary shell command execution may be added to the structured security adapter. Keep tool IDs and argument schemas allowlisted. Require explicit approval for each invocation and explicit authorisation for network checks.
