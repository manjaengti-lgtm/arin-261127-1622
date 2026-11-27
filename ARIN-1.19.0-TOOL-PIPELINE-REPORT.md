# Arin 1.19.0 — Tool pipeline integration report

## What changed

- Added `ToolPipeline`, a single fixed allowlist for the 18 entries in `tool-registry.json`.
- Added AI bridge operations: `tool_catalogue`, `tool_status`, `tool_install`, and `tool_run`.
- Added per-tool install/check controls to Security → Tools.
- Added runtime verification for each local command. A version/help smoke test is explicitly not treated as proof of complete functionality.
- Added pipx support and PATH handling for Semgrep and Bandit.
- Updated the primary AI's security prompt with the complete pipeline contract and argument schemas.
- External tool inputs are restricted to imported paths under `/root/files` in Arin's Ubuntu/PRoot environment. Directory scans are bounded to 5,000 files and 128 MB.
- SQLite execution is read-only and limited to one SELECT or table_info PRAGMA statement.
- Nmap is limited to one explicitly authorised host, TCP connect mode, top 100 ports and a host timeout. testssl requires online mode and explicit authorisation.
- ZAP and Kismet are represented honestly as remote/hardware-dependent and are not falsely reported as locally working.

## Catalogue integration matrix

| Tool | Install route | Execution adapter | Local limitation |
|---|---|---|---|
| JADX | APK toolkit installer | APK decompile | Requires Java/APK toolkit |
| Apktool | APK toolkit installer | APK resource decode | Rebuild/signing is a separate workflow |
| Androguard | APK toolkit installer | APK analysis CLI | Exact CLI command must be runtime-tested |
| Nmap | apt | Bounded authorised TCP check | Requires explicit scope |
| TShark | apt | Offline PCAP protocol summary | Live capture not promised |
| Wireshark CLI | apt package, uses TShark | Offline PCAP protocol summary | GUI not included |
| YARA | apt | Rules + sample scan | Requires local rules file |
| ClamAV | apt | Private-file scan | Signatures should be refreshed separately |
| Binwalk | apt | File/firmware inspection | Large firmware inputs are bounded |
| Sleuth Kit | apt | MMLS partition listing | Requires forensic image |
| SQLite | apt | Read-only query | Single SELECT/table_info only |
| Semgrep | pipx | Local-rule source scan | Requires local rules path; no rule download during scan |
| Bandit | pipx | Python source scan | Python only |
| ShellCheck | apt | Shell script lint | Shell scripts only |
| Trivy | Official/manual install | Offline filesystem scan with DB update skipped | Existing local vulnerability DB required |
| testssl.sh | Official/manual install | Fast TLS assessment | Online + explicit authorisation |
| OWASP ZAP | Remote/desktop setup | Not locally executable in this build | No remote ZAP endpoint connector yet |
| Kismet | Compatible Linux hardware | Not locally executable in Android PRoot | Requires monitor-mode-capable hardware/driver |

## AI invocation protocol

The primary model can request one adapter per response using the existing `<security_tool>{...}</security_tool>` protocol. The app presents the existing approval prompt, executes the fixed adapter, returns stdout/stderr/exit code, records an audit entry and saves successful output. The model must wait for the actual result and may then request the next step.

Examples:

- `{"id":"tool_catalogue","args":{}}`
- `{"id":"tool_status","args":{}}`
- `{"id":"tool_install","args":{"tool":"nmap"}}`
- `{"id":"tool_run","args":{"tool":"tshark","path":"/root/files/attachments/capture.pcapng"}}`
- `{"id":"tool_run","args":{"tool":"nmap","target":"192.0.2.10","authorised":true}}`
- `{"id":"tool_run","args":{"tool":"sqlite3","path":"/root/files/attachments/app.db","query":"SELECT name,type FROM sqlite_master LIMIT 50;"}}`

## Important verification status

Source and registry integration is implemented. The actual binaries have not been installed or executed in this build environment. The Android Gradle build was attempted but could not start because Gradle 8.14.3 was unavailable and `services.gradle.org` could not be reached. Therefore Kotlin compilation, Android UI runtime and device execution remain unverified. The next validation must happen in Claude's build environment or on-device.
