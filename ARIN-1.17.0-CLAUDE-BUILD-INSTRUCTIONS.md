# Claude build instructions — Arin 1.17.0

1. Open this complete source project. Read `PROTECTED_RULES.md` first. Do not modify `ContentGate.kt` if it exists in the working checkout; do not weaken protected safety or approval checks.
2. Audit the new `SecurityToolBridge.kt`, `Prompt.kt`, `ChatViewModel.kt`, `AutopilotScreen.kt`, `SecurityIntelligence.kt`, adapter registry and Gradle version change.
3. Confirm the `<security_tool>` parser is reached through `Prompt.agentAction`, every invocation goes through `askToRun`, and no security adapter can bypass the approval gate.
4. Fix compilation issues without replacing existing modules or adding placeholder implementations.
5. Run `./gradlew :app:compileDebugKotlin :app:testDebugUnitTest :app:lintDebug assembleDebug --no-daemon` (split tasks if needed).
6. Test the bridge with capability_report, network_info, evidence_verify, a harmless imported APK/source file, and a tool version check. Confirm web_passive is blocked in offline mode and without explicit authorisation.
7. Test malformed JSON, unknown adapter IDs, oversized files, path traversal, missing tools, denied approval and network errors.
8. Verify no arbitrary shell command can be supplied through `<security_tool>`. Existing `<run>` terminal functionality remains subject to its existing approvals.
9. Report exact commands, exit codes, APK path, tests run, and any failures. Never claim a build or runtime test passed unless it actually did.
