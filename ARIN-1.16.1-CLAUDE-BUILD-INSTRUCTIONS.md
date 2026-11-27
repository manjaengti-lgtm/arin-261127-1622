# Arin 1.16.1 — build and AI integration verification

Use this source tree as the only source of truth. Version: 1.16.1, versionCode 256, applicationId com.arin.app.

1. Read PROTECTED_RULES.md and ARIN-1.16.1-AI-INTEGRATION-REPORT.md.
2. Preserve all protected files, signing configuration, package ID, existing features and user data. Do not modify ContentGate.kt if present.
3. Audit the changed Kotlin code and compile it. Do not claim success without an actual successful build.
4. Run `./gradlew --version`, then `./gradlew :app:clean :app:testDebugUnitTest :app:lintDebug :app:assembleDebug --stacktrace`.
5. Fix all root-cause groups together, then rerun tests and build.
6. Verify the new AI system-prompt capability context and the Autopilot AI planning handoff using a configured provider. Confirm the AI does not claim to execute actions merely because it received the registry.
7. Verify offline mode and all existing per-action approvals.
8. Test bounded ZIP inspection, including binary expansion limits and traversal-like entry names.
9. Test existing APK, Web, Network, Evidence and Tools screens.
10. Report exact commands, exit codes, APK path, SHA-256, device/provider tests and all remaining limitations.

The capability registry is descriptive context, not a new unrestricted execution interface. Do not bypass permissions, user approvals or protected rules.
