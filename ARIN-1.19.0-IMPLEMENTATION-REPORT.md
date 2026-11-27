# Arin 1.19.0 — Complete catalogue pipeline integration

## Release summary

This release connects the complete 18-entry defensive tool catalogue to one AI-callable execution pipeline and the Security → Tools screen. The AI can request catalogue discovery, runtime status, allowlisted installation and allowlisted execution. Existing per-action approval remains in place.

## Tool coverage

| Tool | Pipeline action | Runtime constraints |
|---|---|---|
| JADX | APK decompile | Ubuntu/PRoot + APK toolkit + Java |
| Apktool | APK decode | Ubuntu/PRoot + APK toolkit |
| Androguard | APK/DEX analysis CLI | Ubuntu/PRoot + APK toolkit; CLI behaviour must be tested |
| Nmap | Bounded TCP connect/service check | One authorised host only; approval and online mode |
| TShark | Offline PCAP protocol summary | Imported PCAP in `/root/files` |
| Wireshark CLI | Offline PCAP protocol summary via TShark | CLI only, no GUI |
| YARA | Rules-based sample scan | Both sample and rules imported under `/root/files` |
| ClamAV | Signature-based file scan | Imported file; signatures should be updated |
| Binwalk | Firmware/file inspection | Imported file under `/root/files` |
| Sleuth Kit | Partition map inspection (`mmls`) | Imported forensic image |
| SQLite | Read-only query | One SELECT or `PRAGMA table_info`; write statements blocked |
| Semgrep | Static source scan | Local rules required; no rule download during execution |
| Bandit | Python static security scan | Imported Python file/directory |
| ShellCheck | Shell lint | Imported `.sh`/`.bash` file |
| Trivy | Offline filesystem scan | Manual official install and pre-existing local DB required |
| testssl.sh | Fast TLS configuration assessment | Manual official install, online mode and explicit authorisation |
| OWASP ZAP | Catalogue/status reporting | Remote/desktop only; no remote ZAP endpoint connector in this release |
| Kismet | Catalogue/status reporting | Compatible hardware/driver required; not locally executable in Android PRoot |

## Pipeline details

- `tool_catalogue`: describes all 18 entries and environment limitations.
- `tool_status`: checks actual command responses for locally executable tools; remote/hardware-only entries are labelled `NOT_LOCAL`.
- `tool_install`: uses fixed installation routes; does not accept arbitrary package commands.
- `tool_run`: fixed command allowlist with per-tool argument validation.
- `tool_smoke_test`: legacy small allowlist retained for compatibility.
- Security actions continue through the app's existing user-approval prompt.
- Nmap and testssl require `authorised=true`; offline mode blocks network adapters.
- External CLI inputs must be imported into Arin Linux at `/root/files/...`; symlink/path traversal is rejected and input sizes are bounded.
- Directory inputs are limited to 5,000 files and 128 MB total.
- Shell command text is never accepted from the model in `tool_run`.
- Tool output, exit code and error are returned to the model and recorded in Arin's reliability audit.

## Honest limitations

The 18 tools are registered and routed, but they are not all guaranteed to be installable or executable on an Android phone. ZAP requires a configured remote/desktop environment, Kismet requires supported wireless hardware, and Trivy/testssl still need manual official installation. Androguard's CLI invocation and every tool's actual runtime behaviour need on-device fixture testing. A command version/help smoke test is not a complete feature test.

## Verification performed in this environment

- ZIP integrity: passed after packaging.
- Adapter/tool registry JSON parsing: passed.
- Existing installer and verifier shell syntax: passed.
- Kotlin parser check: no syntax/expecting errors identified in the new pipeline files; full Kotlin type-check was not possible because Android/Gradle dependencies were unavailable.
- Gradle compile attempt: blocked before project compilation because Gradle 8.14.3 was not cached and `services.gradle.org` could not be reached.
- No tools were installed or executed on an Android device in this environment.

Therefore this is source integration, not a verified APK release. Claude/device validation remains required.
