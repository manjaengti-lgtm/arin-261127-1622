# Claude build and validation instructions — Arin v1.18.0

Use this complete source tree. Do not start from an older ZIP.

1. Read `PROTECTED_RULES.md` and this implementation report first.
2. Preserve existing architecture, signing configuration, app identity and all existing functionality. Do not modify `ContentGate.kt`.
3. Audit `ReliabilityEngine.kt`, `SecurityToolBridge.kt`, `SecurityIntelligence.kt`, `AutopilotScreen.kt`, and the structured security-tool instructions in `ChatViewModel.kt` as one integration.
4. Check Kotlin/Android API compatibility, Compose imports, coroutine usage, JSON APIs, task-ledger persistence, audit hash-chain reconstruction and error paths.
5. Fix issues in a consolidated pass. Do not replace implementations with placeholders or remove features to make the build pass.
6. Build with the project's configured Gradle wrapper; run unit tests and lint; assemble debug APK.
7. Test local reliability self-test, task creation/update/list, audit append/verification, audit tampering detection, resource report, result evaluation, finding deduplication and adapter approval gates.
8. Test offline-mode rejection of network adapters and verify that no arbitrary shell command can be passed through the structured bridge.
9. Test Autopilot task creation and AI planning prompt, then test a real provider response and a user-approved adapter invocation if credentials/network are available.
10. Report exact commands, exit codes, APK path, device/emulator test results and every unverified limitation. Never report a source-level self-test as proof of a successful APK build or live AI connection.

If a dependency download or provider is unavailable, preserve the work and continue independent static checks. Do not bypass model safety controls or conceal the purpose of any security operation.
