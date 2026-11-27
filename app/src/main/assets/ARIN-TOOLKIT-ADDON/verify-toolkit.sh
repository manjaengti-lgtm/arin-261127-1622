#!/usr/bin/env bash
# Presence + harmless execution smoke tests; no scans or network probes are performed.
set +e
export PATH="/opt/pipx/bin:/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
check() {
  label="$1"; shift
  if command -v "$1" >/dev/null 2>&1; then
    path="$(command -v "$1")"
    if timeout 15 "$@" >/tmp/arin-tool-check.out 2>&1; then
      printf 'WORKING\t%s\t%s\n' "$label" "$path"
    else
      rc=$?; printf 'PRESENT_NOT_VERIFIED\t%s\t%s (smoke exit %s)\n' "$label" "$path" "$rc"
    fi
  else printf 'MISSING\t%s\t-\n' "$label"; fi
}
check jadx jadx --version
check apktool apktool --version
check androguard androguard --help
check nmap nmap --version
check tshark tshark --version
check yara yara --version
check clamscan clamscan --version
check binwalk binwalk --help
check fls fls -V
check sqlite3 sqlite3 --version
check semgrep semgrep --version
check bandit bandit --version
check shellcheck shellcheck --version
check trivy trivy --version
check testssl.sh testssl.sh --version
check zap.sh zap.sh -version
check kismet kismet --version
