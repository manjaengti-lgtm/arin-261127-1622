# Arin 1.16.0 — Implementation report

## Implemented in this source update

- Added an Investigation Autopilot tab to the Security workstation.
- Added a capability/adapter registry in Kotlin and a machine-readable JSON registry in assets.
- Added an offline-mode preference. Network assessment from Autopilot is disabled while offline mode is enabled.
- Added bounded APK/ZIP/AAB/JAR and source-file inspection. Archive entries are inspected without extraction or execution, with entry-count and byte limits.
- Added partial dependency inventory for Gradle declarations, Maven XML, package.json dependencies and Python requirements.
- Added a partial CycloneDX 1.5-style component JSON section. This is explicitly not a complete dependency-resolved SBOM.
- Added redacted heuristic checks for common private-key, AWS, GitHub-token, API-key and password patterns.
- Added passive web assessment from Autopilot, gated by explicit user authorisation confirmation.
- Added local capability report generation, report export, clipboard copy and Ask Arin to explain.
- Connected natural-language Security Agent requests for SBOM/source/archive/secret-scan/autopilot to the new tab.
- Added the capability registry to the Security report handoff prompt so the model can distinguish available adapters and their limitations.
- Updated app version to 1.16.0 and versionCode 255.

## Existing systems retained

The existing APK audit, WebAudit, NetAudit, Forensics, VulnIntel, toolkit installer and verification UI remain in place. Existing protected rules, Gradle wrapper, signing setup, GitHub workflow and original application modules were not intentionally rewritten.

## Not claimed as complete

- Full transitive SBOM resolution and automated SCA correlation are not implemented by this offline scanner.
- Dynamic APK sandbox execution is not implemented.
- Native binary decompilation still depends on separately installed compatible tools.
- A true 3D network topology map is not implemented.
- Local on-device LLM inference depends on a separately configured model/runtime.
- Automatic source-code repair remains governed by the existing Arin update/build workflows and user approval rules.
- Runtime behaviour of third-party tools and device-specific compatibility still require testing on the target phone.

## Verification

- Source-level archive and syntax checks are required after packaging.
- Gradle compilation could not be completed in this environment because the Gradle distribution was not cached and network access to services.gradle.org was unavailable.
- Do not treat the source ZIP as a verified APK build.
