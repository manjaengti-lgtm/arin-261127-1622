# Arin 1.16.1 — AI integration audit and changes

## AI integration audit of 1.16.0

The previous release had a partial AI connection:
- The Autopilot screen performed local source/archive analysis and passive web assessment itself.
- The user could send a completed report to the chat model for explanation.
- The Security Agent used keyword routing to open relevant screens.
- The model capability registry was included in selected report handoffs.

It was not a full autonomous tool-using security agent. The primary model did not receive the capability registry in its normal system context for security requests, and Autopilot did not have a dedicated AI planning handoff for the user's investigation objective. The adapter registry described capabilities but did not itself execute tools.

## Changes in 1.16.1

- The primary chat model now receives the security capability registry when the latest user request is recognisably security-related.
- The capability note now includes live Linux/PRoot, Java/Kotlin/Gradle, Android SDK and APK-toolkit installation markers when a Context is available.
- The prompt explicitly distinguishes installation markers from successful runtime tests and tells the model not to claim unverified tools work.
- Autopilot now has an **Ask Arin AI to plan this investigation** action. It sends the user's objective, target, authorisation state, offline-mode state and capability registry to the normal chat model.
- The AI planning handoff does not execute a scan. Existing UI controls and approval gates remain responsible for operations.
- Archive inspection now counts decompressed bytes for binary entries as well as text entries, limiting ZIP-bomb expansion to 128 MiB total. It does not extract or execute archive contents.
- Version updated to 1.16.1 / versionCode 256.

## AI integration status

| Function | Status | Evidence / limitation |
|---|---|---|
| AI receives capability registry for security requests | Implemented in source | Added to primary model system prompt when the latest request matches security topics; requires runtime test with configured provider |
| AI receives Linux/toolkit installation markers | Implemented in source | Markers are explicitly not treated as runtime smoke tests |
| AI plans an investigation from Autopilot | Implemented in source | Button sends objective and scope context to ChatViewModel |
| AI explains generated reports | Existing | Report handoff sends bounded report text to chat |
| AI independently invokes every SecurityIntelligence adapter | Not implemented | Registry is descriptive; adapters are not all exposed as model-callable tools |
| AI dynamically installs and executes all 18 catalogue tools | Not implemented | Installation and runtime checks remain separate workflows; platform support varies |
| Fully autonomous end-to-end assessment | Not implemented | User file selection, authorisation and action approval remain required |

## Verification performed in this environment

- Source archive extracted and inspected.
- JSON registry parsed successfully with Python's JSON parser.
- Existing toolkit shell scripts passed `bash -n` syntax checks.
- Source package archive integrity checked after packaging.
- Gradle compilation attempted with `./gradlew --offline :app:compileDebugKotlin --stacktrace`.

## Build blocker

Gradle 8.14.3 was not cached. The wrapper attempted to download it from `services.gradle.org`, but DNS/network access failed with `java.net.UnknownHostException`. Therefore Kotlin compilation, Android lint, unit tests, APK assembly and on-device AI/provider tests were not completed. Do not claim the APK is build-verified.

## Required device/provider tests

1. Configure a working AI provider and send a security-related request in ordinary chat. Confirm the model receives the capability note and correctly reports tool limitations.
2. Open Security → Autopilot → enter an investigation objective → tap **Ask Arin AI to plan this investigation**. Confirm the normal chat opens and the configured primary model responds with a scoped plan.
3. Repeat with Offline mode enabled and confirm the AI does not propose network operations.
4. Confirm installation markers are not described as successful tool execution.
5. Inspect a test ZIP containing ordinary text files, binary files and traversal-like entry names; verify the report is bounded and no files are extracted or executed.
6. Run Gradle tests, lint and assembleDebug in an environment with the configured Android SDK and Gradle distribution.
