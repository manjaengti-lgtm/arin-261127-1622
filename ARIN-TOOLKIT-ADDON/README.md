# Arin Security Toolkit Add-on — v1.15.4

This add-on is packaged separately from Arin's existing Kotlin/Java source. Existing source files are preserved. The only existing project-file adjustment is the Android version metadata in `app/build.gradle.kts` (1.15.3/253 → 1.15.4/254) so a future APK can be installed as an in-place update, provided the signing certificate matches.

## Contents

- `tool-registry.json`: machine-readable catalogue of defensive, diagnostic, reverse-engineering, forensic and controlled-lab tools, with realistic platform limitations.
- `install-defensive-toolkit.sh`: optional Ubuntu/PRoot installer for a selected baseline of defensive and analysis packages. It does not run scans or attack targets.
- `verify-toolkit.sh`: reports which catalogue tools are present.
- `ASSESSMENT-SCOPE-TEMPLATE.md`: scope/authorization record template.
- `INTEGRATION-NOTES.md`: explains how this add-on relates to the existing Arin Security screen.

## Important integration boundary

The current app's `SecurityScreen.kt`, `ApkAudit.kt`, `NetAudit.kt`, `WebAudit.kt`, `VulnIntel.kt` and `Forensics.kt` remain unchanged. Adding assets alone does not make the app UI invoke them. The scripts can be run from Arin's built-in Ubuntu/PRoot terminal after extracting this add-on. Automatic in-app invocation requires a future source-code integration and is deliberately not claimed here.

## Install baseline tools

From Arin's Ubuntu/PRoot shell, copy/extract this add-on to a writable directory, then run:

```sh
bash install-defensive-toolkit.sh
bash verify-toolkit.sh
```

The installer uses the configured Ubuntu package repositories and installs only packages available there. Review the package list before running. Some tools may require capabilities unavailable in Android/PRoot; the verifier reports presence, not full operational capability.

## Safety and scope

Use active discovery and testing only on systems you own or are explicitly authorised to assess. This add-on does not automate exploitation, credential attacks, persistence, evasion, or destructive actions. Packet capture and wireless monitor mode may require root, drivers and hardware that ordinary Android/PRoot does not provide.


## v1.15.4 integration completion notes

The Security → Tools screen includes baseline installation, the existing APK toolkit updater, and harmless command smoke tests. The primary model receives the toolkit's supported capabilities and platform restrictions through the terminal environment description. Read `INTEGRATION-STATUS.md` for exact installation and runtime limitations.
