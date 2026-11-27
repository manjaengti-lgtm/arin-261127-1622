#!/usr/bin/env bash
# Arin defensive/security analysis toolkit installer for Ubuntu/Debian in PRoot.
# Installs only defensive diagnostics and static/offline analysis utilities.
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export PIPX_HOME=/opt/pipx
export PIPX_BIN_DIR=/usr/local/bin
export PATH="$PIPX_BIN_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run inside Arin Ubuntu/PRoot root shell." >&2; exit 1
fi
command -v apt-get >/dev/null 2>&1 || { echo "Ubuntu/Debian apt environment required." >&2; exit 2; }

BASE=(ca-certificates curl wget unzip zip file xxd jq sqlite3 binutils git python3 python3-pip python3-venv pipx dnsutils whois openssl shellcheck nmap yara clamav binwalk sleuthkit)
OPTIONAL=(tshark wireshark-common apktool jadx testssl.sh trivy)
INSTALLED=(); SKIPPED=(); FAILED=()

printf '\n=== Arin Security Toolkit installer ===\n'
printf 'Environment: '; uname -m
apt-get update
for pkg in "${BASE[@]}" "${OPTIONAL[@]}"; do
  if ! apt-cache show "$pkg" >/dev/null 2>&1; then SKIPPED+=("$pkg (not in configured apt repositories)"); continue; fi
  if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
    INSTALLED+=("$pkg (already installed)"); continue
  fi
  echo "Installing $pkg ..."
  if apt-get install -y --no-install-recommends "$pkg"; then INSTALLED+=("$pkg"); else FAILED+=("$pkg"); fi
done

# Isolated Python CLI applications. Explicit PATH above makes pipx tools available to Arin's noninteractive shell.
if command -v pipx >/dev/null 2>&1; then
  pipx ensurepath >/dev/null 2>&1 || true
  for app in bandit semgrep; do
    if command -v "$app" >/dev/null 2>&1; then INSTALLED+=("$app (already installed)")
    elif pipx install "$app" || pipx upgrade "$app"; then INSTALLED+=("$app (pipx)")
    else FAILED+=("$app (pipx)"); fi
  done
else
  SKIPPED+=("Bandit/Semgrep (pipx unavailable)")
fi

# Report commands that need a separate supported host or verified manual installation.
SKIPPED+=("OWASP ZAP (desktop/remote Linux recommended; GUI and memory requirements)")
SKIPPED+=("Kismet (requires compatible wireless adapter, driver and permissions)")
SKIPPED+=("Trivy/testssl.sh (installed only if packages exist in configured repositories)")

printf '\n=== Installation summary ===\n'
printf 'Installed/available packages: %s\n' "${#INSTALLED[@]}"
printf 'Skipped: %s\n' "${#SKIPPED[@]}"
printf 'Failed: %s\n' "${#FAILED[@]}"
printf '\n'
printf 'INSTALLED: %s\n' "${INSTALLED[@]:-none}"
printf 'SKIPPED: %s\n' "${SKIPPED[@]:-none}"
printf 'FAILED: %s\n' "${FAILED[@]:-none}"
printf '\nInstallation stage finished. Run Arin Verify for execution smoke tests.\n'
((${#FAILED[@]} == 0))
