#!/usr/bin/env bash
# Install diagnostic/recovery helpers only; no services, routes or accounts change.
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$EUID" -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
command -v python3 >/dev/null
command -v curl >/dev/null
python3 - "$REPO_DIR" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
for name in ('connectivity/connectivityctl', 'connectivity/aether_runner.py',
             'connectivity/transport_health.py', 'connectivity/limited_access_probe.py',
             'connectivity/recovery_bundle.py', 'scripts/probe-limited-access.py',
             'scripts/rescue-bootstrap.py'):
    path = root / name
    compile(path.read_text(), str(path), 'exec')
PY
install -d -m 0755 /opt/connectivity-tools/rescue /usr/local/sbin
install_atomic() {
  local source="$1" target="$2" mode="$3" pending
  pending="$(mktemp "${target}.pending.XXXXXX")"
  if install -m "$mode" "$source" "$pending" && mv -fT "$pending" "$target"; then
    return 0
  fi
  rm -f "$pending"
  return 1
}
for name in aether_runner.py transport_health.py limited_access_probe.py recovery_bundle.py; do
  install_atomic "$REPO_DIR/connectivity/$name" "/opt/connectivity-tools/rescue/$name" 0644
done
install_atomic "$REPO_DIR/connectivity/connectivityctl" /usr/local/sbin/connectivityctl 0755
install_atomic "$REPO_DIR/scripts/probe-limited-access.py" /usr/local/sbin/rescue-access-probe 0755
install_atomic "$REPO_DIR/scripts/rescue-bootstrap.py" /usr/local/sbin/rescue-bootstrap 0755
echo 'Installed: connectivityctl diagnose --json; rescue-access-probe --help; rescue-bootstrap --help'
