#!/bin/sh
# Check that sochandoff is ready. Prints variable NAMES only, never values.
set -u

ok() { printf '  [ok]   %s\n' "$1"; }
no() { printf '  [--]   %s\n' "$1"; }

echo "sochandoff doctor"

if command -v python3 >/dev/null 2>&1; then
  v=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    ok "python $v"
  else
    no "python $v (need 3.11+)"
  fi
else
  no "python3 not found"
fi

if command -v sochandoff >/dev/null 2>&1; then
  ok "$(sochandoff --version)"
else
  no "sochandoff not installed: pip install git+https://github.com/ARUSHUGAL/sochandoff.git"
fi

cfg="${HOME}/.sochandoff/config.toml"
if [ -f "$cfg" ]; then ok "config $cfg"; else no "no config (defaults used): $cfg"; fi

check_group() {
  label=$1; shift
  missing=""
  for name in "$@"; do
    eval "val=\${$name:-}"
    [ -n "$val" ] || missing="$missing $name"
  done
  if [ -z "$missing" ]; then ok "$label ready"; else no "$label missing:$missing"; fi
}

check_group "thehive" SOCHANDOFF_THEHIVE_URL SOCHANDOFF_THEHIVE_KEY
check_group "wazuh" SOCHANDOFF_WAZUH_URL SOCHANDOFF_WAZUH_USER SOCHANDOFF_WAZUH_PASS
check_group "live intel" SOCHANDOFF_ABUSEIPDB_KEY
