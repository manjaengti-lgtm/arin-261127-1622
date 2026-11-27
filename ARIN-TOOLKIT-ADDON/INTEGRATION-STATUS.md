# Toolkit integration status — v1.15.4

The Security → Tools screen now offers two install paths: the defensive baseline installer and the existing dedicated APK toolkit updater. Verify runs harmless version/help smoke tests and labels commands that execute successfully. A successful smoke test does not prove every operational feature or Android hardware capability.

## Catalogue

| Tool | Installation path | Runtime caveat |
|---|---|---|
| JADX | Existing APK toolkit updater | Requires compatible Java/runtime |
| Apktool | Existing APK toolkit updater | APK rebuild may require Android build components |
| Androguard | Existing APK toolkit updater | Python package and architecture compatibility |
| Nmap | apt package when available | Only explicitly authorised targets; PRoot limits raw sockets |
| TShark / Wireshark CLI | apt packages when available | Offline capture analysis preferred; live capture may be unavailable |
| YARA | apt package | Rule quality determines detection |
| ClamAV | apt package | Update signatures; no guarantee of detection |
| Binwalk | apt package | Firmware extraction depends on version/features |
| The Sleuth Kit | apt package | Disk-image access and filesystem support vary |
| SQLite | apt package | Database access depends on file permissions/format |
| Semgrep / Bandit | pipx isolated installs | PATH is explicitly exported for noninteractive PRoot execution |
| ShellCheck | apt package | Static shell analysis |
| Trivy | apt package only if present in configured repositories | Otherwise remains unavailable; no unverified binary is downloaded |
| testssl.sh | apt package only if present in configured repositories | Otherwise remains unavailable; no unverified binary is downloaded |
| OWASP ZAP | Listed; desktop/remote Linux | GUI, memory and Java requirements make phone/PRoot unsuitable in many cases |
| Kismet | Listed; hardware-dependent | Requires supported wireless adapter, driver and permissions |

## AI integration

`Shell.describe()` now exposes the toolkit's capabilities and limitations to the primary model in both built-in PRoot Linux and Termux. The model is instructed to verify command availability, prefer static/passive/offline work, and respect explicit authorisation scope. The existing AgentTools installer blocks tool names explicitly excluded by the protected security-workstation policy.

## Deliberately excluded by the existing protected rules

Metasploit, sqlmap, Hydra, John the Ripper, Hashcat, Gobuster, ffuf, Bettercap and Aircrack-ng are not added to the install catalogue or AI installation path. `PROTECTED_RULES.md` explicitly excludes attack/credential tools and active injection/access-control/Wi-Fi attack capabilities. Those owner-protected rules were preserved, not weakened.

## Verification limits

The installer and verifier were syntax-checked locally. No apt installation was run here, no PRoot environment was available, and no Android device test or successful Gradle build has been performed. The app must be compiled and the install/verify buttons tested on-device before this integration can be marked release-verified.
