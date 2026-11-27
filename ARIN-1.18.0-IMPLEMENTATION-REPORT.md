# Arin v1.18.0 — Reliability & Investigation Continuity

## Added in this source update

- `ReliabilityEngine.kt`: private persistent task ledger with task statuses PENDING, IN_PROGRESS, BLOCKED, TESTING, COMPLETED, VERIFIED and FAILED.
- Hash-chained JSONL execution audit. Each security adapter invocation records adapter ID, exit code and output/error lengths; raw command output and user secrets are not copied into the audit metadata.
- Audit-chain verification that detects changed, removed or reordered records in the current log. This is tamper-evident, not tamper-proof against a privileged attacker able to replace the entire app-private directory.
- Device resource snapshot for Android version, supported ABIs, available RAM and app-filesystem free space.
- Local self-tests for private storage, task ledger, SHA-256, JSON parsing, offline preference access and audit append/verification.
- Conservative execution-result evaluation: distinguishes FAILED, INCONCLUSIVE and EXECUTED_WITH_OUTPUT. A zero exit code is explicitly not proof that a security finding is valid.
- Exact-match finding deduplication by title and artifact. It does not infer causality or vulnerability validity.
- New structured AI bridge IDs: `reliability_self_test`, `resource_report`, `audit_verify`, `task_list`, `task_create`, `task_update`, `result_evaluate`, `finding_correlate`.
- Autopilot creates a persistent task record before asking the primary AI to plan; the AI is instructed to update the ledger as progress changes.
- Autopilot UI exposes self-test, audit verification, resource snapshot and task ledger.

## Existing behaviour and controls

- Existing per-action approval flow remains the gate for structured security tool actions.
- Network operations remain subject to offline-mode and explicit authorisation checks.
- The bridge still does not expose arbitrary shell execution.
- Imported-file analysis remains restricted to Arin private files/cache paths and existing size limits.
- No destructive, stealth, credential-theft or unauthorised testing operations were added.
- `PROTECTED_RULES.md` and signing configuration were not changed. `ContentGate.kt` was not modified.

## Limitations — do not represent these as completed

- Task records persist state but do not schedule or automatically resume operations after process death.
- The audit chain is stored in app-private storage and is not a hardware-backed or remote immutable log.
- Finding correlation is exact-match deduplication, not semantic correlation.
- Resource information is a point-in-time estimate, not a resource reservation or sandbox.
- Self-tests validate local primitives, not Android compilation, provider connectivity, emulator/device behaviour or third-party tool correctness.
- Full transitive SBOM resolution, dynamic APK sandboxing, native decompilation and a multi-agent verification workflow remain separate work.

## Validation performed here

- Source archive integrity checked.
- Original v1.17.0 archive entries preserved; additions and targeted edits only.
- JSON and shell scripts in the source package checked where applicable.
- Kotlin compiler parser pass on the new Kotlin file produced no syntax/`expecting` diagnostics, but standalone compilation cannot resolve Android and org.json classes without the Android SDK classpath.
- Gradle compilation attempted with `./gradlew --offline :app:compileDebugKotlin --no-daemon`; it could not start because Gradle 8.14.3 was not cached and the environment could not resolve `services.gradle.org`.

**Build status: NOT VERIFIED.** No APK build or device execution is claimed.
