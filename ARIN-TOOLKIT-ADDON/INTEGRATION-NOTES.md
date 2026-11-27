# Integration notes

## Existing code inspected

The supplied archive already contains a Security area under `app/src/main/java/com/arin/security/`:

- `SecurityScreen.kt`
- `ApkAudit.kt`
- `NetAudit.kt`
- `WebAudit.kt`
- `VulnIntel.kt`
- `Forensics.kt`

It also includes an APK toolkit setup script at `app/src/main/assets/apk-toolkit-setup.sh`, Linux/PRoot support, Termux support, MCP bridges and GitHub build workflows.

## What this add-on does

It adds a standalone tool registry and optional Ubuntu/PRoot package installer under `app/src/main/assets/ARIN-TOOLKIT-ADDON/`. Android automatically packages files placed under the assets directory, but the existing Kotlin code does not automatically execute new scripts or parse this registry.

## What it does not claim

- It does not claim all listed tools are installed.
- It does not claim the S25 Ultra supports root-only wireless operations.
- It does not claim that installing a CLI package automatically integrates it into Arin's AI orchestration.
- It does not claim an APK has been compiled or tested.

A future UI integration can read the registry, check executable availability, expose only supported operations, and return tool output to the primary model. That requires modifying application source and is outside this source-preserving add-on.
