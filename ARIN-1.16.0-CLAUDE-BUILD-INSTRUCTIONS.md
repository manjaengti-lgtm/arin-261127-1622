# Claude build handoff — Arin 1.16.0

Use this complete source tree as the only source of truth. Do not merge an older ZIP over it.

## Objective
Compile, test and repair Arin 1.16.0 (applicationId `com.arin.app`, versionCode `255`, versionName `1.16.0`) while preserving the existing app and all protected rules.

## New implementation files
- `app/src/main/java/com/arin/security/SecurityIntelligence.kt`
  - capability/adapter registry, persistent offline-mode preference, report storage and bounded static source/archive analysis.
- `app/src/main/java/com/arin/security/AutopilotScreen.kt`
  - Investigation Autopilot UI, source/archive inspection, passive web assessment with explicit permission, capability report and report export.
- `app/src/main/assets/ARIN-INTELLIGENCE/adapter-registry.json`
  - machine-readable adapter catalogue.
- `ARIN-1.16.0-IMPLEMENTATION-REPORT.md`
  - implemented features and known limitations.

## Existing files changed
- `app/build.gradle.kts`: versionCode 255 / versionName 1.16.0.
- `app/src/main/java/com/arin/security/SecurityScreen.kt`: adds Autopilot tab, natural-language routing for source/SBOM/secret-scan requests and includes capability facts in the report-to-chat handoff.

## Mandatory protected-file rules
- Read `PROTECTED_RULES.md` first.
- Do not modify `PROTECTED_RULES.md`, `.github/`, Gradle wrapper files, `settings.gradle.kts`, signing key/configuration, protected AI helper/team/task-summary/update behaviour, or any file marked `ARIN-PROTECTED`.
- Do not change `ContentGate.kt` if it exists in any branch or generated source.
- Do not weaken existing tool exclusions or scope confirmation.
- Do not add stealth, credential theft, destructive, persistence or unauthorised access features.
- Preserve existing chats, user settings, stored project data and app ID.

## Build and validation procedure
1. Inspect the full diff and verify only the two existing source files above changed, plus the new files listed above and this handoff documentation.
2. Run `./gradlew --version` and confirm JDK compatibility.
3. Run `./gradlew :app:clean :app:testDebugUnitTest :app:lintDebug :app:assembleDebug --stacktrace`.
4. Fix all compile errors as a group after inspecting complete logs. Do not use blind one-error-at-a-time edits.
5. Add focused tests for `SourceAudit` dependency extraction, secret redaction, archive traversal rejection and archive-size/entry bounds if the test dependencies are already available. Do not add large dependencies without justification.
6. Verify the Security tab opens, Autopilot tab opens, offline mode persists after app restart, network action remains disabled offline, authorisation is required online, source archives are not extracted or executed, and report export works.
7. Verify existing APK, Web, Network, Evidence and Tools tabs still work.
8. Verify APK signature compatibility with the existing bundled signing key; never replace the key.
9. Report exact commands, exit codes, warnings, APK path, SHA-256 and device/emulator tests actually performed.

## Important implementation limitations
- The SBOM is a partial direct-dependency inventory, not a complete transitive or lockfile-resolved SBOM.
- Secret scanning is heuristic and redacts matches; false positives and misses are possible.
- No dynamic APK sandbox or full native decompiler is implemented by this addition.
- Existing network checks are passive/ordinary TCP checks and require permission.
- A registry entry does not prove a third-party tool is installed. Keep statuses honest.

## Completion requirement
Do not stop at documentation or placeholder controls. Complete the build, run available tests, fix integration errors, and provide a factual implementation/test report. If a platform limitation blocks a step, preserve the working source and report the exact blocker rather than claiming success.
