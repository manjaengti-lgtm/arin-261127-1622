# Arin 1.15.4 — Toolkit Integration / Claude Build Instructions

This source tree now contains the toolkit integration. Do not treat this as an instruction to bypass safety controls or to claim unsupported hardware capabilities.

## Changes already integrated
- Added `ToolkitScreen.kt`, a Security → Tools tab showing all 18 tools in `tool-registry.json`.
- Added an in-app action to copy and run `install-defensive-toolkit.sh` inside Arin's Ubuntu/PRoot root filesystem through `Linux.run`.
- Added a command-presence verification action and per-tool presence display.
- Added Semgrep to the optional pipx install attempt alongside Bandit.
- Preserved existing APK, Web, Network, Evidence and Agent tabs and existing audit implementations.
- Bumped app version to 1.15.4 / versionCode 254.

## Required Claude tasks
1. Inspect the entire source tree and the diff before changing anything.
2. Compile `:app:assembleDebug` using the repository's configured Gradle wrapper and the project's existing JDK/AGP/Kotlin versions. Do not upgrade versions speculatively.
3. Fix all compile errors caused by this integration, including Compose API/import/coroutine overload issues. Keep changes minimal.
4. Run available unit tests, lint and the project's existing `.github/arin-test.sh` checks where practical. Report commands and actual exit codes.
5. Verify that `ARIN-TOOLKIT-ADDON/tool-registry.json` and both shell scripts are packaged in app assets.
6. Review the installer for idempotency, package availability, apt failure handling and pipx PATH behavior. Do not make unsupported packages appear installed.
7. Verify Security tab navigation: tab index 5 must display ToolkitScreen; indices 0–4 must preserve their original behavior.
8. Add integration with Arin's AI tool/capability description only if there is a real existing capability registry to extend. Do not fabricate executable tool APIs. The AI must distinguish installed, missing, unsupported, manual-install and hardware-dependent tools.
9. Do not modify `ContentGate.kt` or any other file marked protected in `PROTECTED_RULES.md`. If a protected file is genuinely required, stop and report the dependency rather than changing it.
10. Do not claim the app or tools work until compiled and runtime-tested. Provide exact build output and a list of tools verified on the target environment.

## Honest platform boundaries
- Baseline installer installs packages available in Ubuntu/Debian repositories and attempts isolated pipx installs for Bandit and Semgrep.
- Trivy and testssl.sh remain catalogued for separate official installation.
- OWASP ZAP is intended for a suitable desktop/remote Linux environment; it may exceed phone/PRoot resources.
- Kismet requires compatible wireless hardware and drivers.
- PRoot is not Android root. Presence of Nmap/TShark/Kismet does not grant raw packet capture, Wi-Fi monitor mode or injection.
- Do not add exploit automation, credential attacks, stealth, persistence or unauthorised access. Keep checks within user-owned or explicitly authorised scope.
