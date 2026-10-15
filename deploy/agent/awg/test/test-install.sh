#!/bin/sh
# Runs install.sh with --stage (everything under a temporary directory, no systemctl, no useradd) and --from
# (local files), and checks what it wrote: the files, their modes, the sudoers rules, the configuration, and
# that a bad checksum or a bad argument stops it before anything is written.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
inst="$here/../install.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }

case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) arch=amd64 ;; esac
rel="$tmp/release"; mkdir -p "$rel"
printf 'fake agent\n' > "$rel/remnascope-agent-linux-$arch"
printf 'fake sensor\n' > "$rel/remnascope-awg-sensor-linux-$arch"
( cd "$root" && tar -czf "$rel/remnascope-deploy-files.tar.gz" deploy/agent/awg/remnascope-awg-snapshot deploy/agent/awg/remnascope-awg-manage \
    deploy/agent/awg/remnascope-awg-container deploy/agent/awg/remnascope-awg-sensors-sync deploy/agent/awg/remnascope-awg-sensors.service deploy/agent/awg/remnascope-awg-sensors.path deploy/agent/awg/remnascope-awg-sensor-run deploy/agent/awg/remnascope-awg.service 'deploy/agent/awg/remnascope-awg-sensor@.service' )
( cd "$rel" && sha256sum remnascope-* > SHA256SUMS )
printf 'agentid.secretsecretsecretsecret\n' > "$tmp/token"

st="$tmp/stage"
sh "$inst" --stage "$st" --from "$rel" --server wss://scope.example.org/ingest/v1 --token-file "$tmp/token" \
  --endpoint-host 203.0.113.10 --managed "amnezia-awg3" --sense "amnezia-awg2 amnezia-awg3" >"$tmp/out" 2>&1 || { cat "$tmp/out"; fail "install failed"; }

for f in usr/local/bin/remnascope-agent-awg usr/local/sbin/remnascope-awg-snapshot usr/local/sbin/remnascope-awg-manage \
         usr/local/sbin/remnascope-awg-sensor usr/local/sbin/remnascope-awg-sensor-run etc/systemd/system/remnascope-awg.service \
         'etc/systemd/system/remnascope-awg-sensor@.service' etc/remnascope/awg.token etc/remnascope/awg-manage.conf \
         etc/sudoers.d/remnascope-awg etc/sudoers.d/remnascope-awg-manage etc/systemd/system/remnascope-awg.service.d/10-remnascope.conf; do
  [ -f "$st/$f" ] || fail "missing $f"
done
grep -qx 'MANAGED="amnezia-awg3"' "$st/etc/remnascope/awg-manage.conf" || fail "MANAGED"
grep -qx 'SENSE="amnezia-awg2 amnezia-awg3"' "$st/etc/remnascope/awg-manage.conf" || fail "SENSE"
grep -qx 'ENDPOINT_HOST="203.0.113.10"' "$st/etc/remnascope/awg-manage.conf" || fail "ENDPOINT_HOST"
grep -q '^CONTAINERS="amnezia-awg2 amnezia-awg3"$' "$st/etc/remnascope/awg-manage.conf" || fail "CONTAINERS"
grep -q 'wss://scope.example.org/ingest/v1' "$st/etc/systemd/system/remnascope-awg.service" || fail "server address in the unit"
grep -q 'scope.example.com' "$st/etc/systemd/system/remnascope-awg.service" && fail "the placeholder address is still in the unit"
grep -qx 'remnascope ALL=(root) NOPASSWD: /usr/local/sbin/remnascope-awg-snapshot' "$st/etc/sudoers.d/remnascope-awg" || fail "snapshot rule"
grep -qx 'remnascope ALL=(root) NOPASSWD: /usr/local/sbin/remnascope-awg-manage' "$st/etc/sudoers.d/remnascope-awg-manage" || fail "manage rule"
# One rule per file, one command each: nothing broader than the two helpers.
[ "$(cat "$st"/etc/sudoers.d/remnascope-awg* | wc -l | tr -d ' ')" = 2 ] || fail "sudoers has more than the two rules"
grep -q 'SENSOR_CONTAINERS=amnezia-awg2,amnezia-awg3"' "$st/etc/systemd/system/remnascope-awg.service.d/10-remnascope.conf" || fail "sensor containers"
[ "$(cat "$st/etc/remnascope/awg.token")" = "agentid.secretsecretsecretsecret" ] || fail "token content"
mode=$(stat -c %a "$st/etc/remnascope/awg.token" 2>/dev/null || stat -f %Lp "$st/etc/remnascope/awg.token")
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) ;; *) [ "$mode" = 640 ] || fail "token mode is $mode" ;; esac
echo "install ok"
# Without --container-admin the helper that creates containers is not installed and has no sudoers rule.
[ ! -e "$st/usr/local/sbin/remnascope-awg-container" ] || fail "the container helper was installed without being asked for"
[ ! -e "$st/etc/sudoers.d/remnascope-awg-container" ] || fail "a container rule exists without being asked for"
st4="$tmp/stage4"
sh "$inst" --stage "$st4" --from "$rel" --server wss://scope.example.org/ingest/v1 --token-file "$tmp/token" \
  --endpoint-host 203.0.113.10 --managed amnezia-awg3 --container-admin >/dev/null 2>&1 || fail "install with --container-admin failed"
[ -f "$st4/usr/local/sbin/remnascope-awg-container" ] || fail "container helper missing"
grep -qx 'remnascope ALL=(root) NOPASSWD: /usr/local/sbin/remnascope-awg-container' "$st4/etc/sudoers.d/remnascope-awg-container" || fail "container rule"
grep -q 'REMNASCOPE_AWG_CONTAINER=/usr/bin/sudo -n /usr/local/sbin/remnascope-awg-container' "$st4/etc/systemd/system/remnascope-awg.service.d/10-remnascope.conf" || fail "container variable"
grep -q 'REMNASCOPE_AWG_CONTAINER' "$st/etc/systemd/system/remnascope-awg.service.d/10-remnascope.conf" && fail "the container variable is set without being asked for"
[ -f "$st4/etc/systemd/system/remnascope-awg-sensors.path" ] && [ -x "$st4/usr/local/sbin/remnascope-awg-sensors-sync" ] || fail "the sensor sync units"
grep -q '^ReadWritePaths=/etc/remnascope$' "$st4/etc/systemd/system/remnascope-awg.service.d/10-remnascope.conf" || fail "the config directory is not writable for the helper"
grep -q 'ReadWritePaths' "$st/etc/systemd/system/remnascope-awg.service.d/10-remnascope.conf" && fail "write access was granted without --container-admin"
echo "container-admin ok"

# A tampered file is refused and nothing is written.
bad="$tmp/bad"; cp -r "$rel" "$bad"; printf 'evil\n' > "$bad/remnascope-agent-linux-$arch"
if sh "$inst" --stage "$tmp/stage2" --from "$bad" --server wss://scope.example.org/ingest/v1 --token-file "$tmp/token" \
     --endpoint-host 203.0.113.10 --managed amnezia-awg3 >/dev/null 2>&1; then fail "a tampered binary was accepted"; fi
[ ! -e "$tmp/stage2/usr/local/bin/remnascope-agent-awg" ] || fail "something was installed from a tampered release"
echo "tamper ok"

# Bad arguments never reach a file.
for args in "--server http://x/ingest/v1" "--server wss://h/ingest/v1;rm" "--managed a;b" "--endpoint-host 'a b'" "--version main"; do
  # shellcheck disable=SC2086
  if sh "$inst" --stage "$tmp/stage3" --from "$rel" --token-file "$tmp/token" --server wss://h.example/ingest/v1 --endpoint-host 203.0.113.10 --managed x $args >/dev/null 2>&1; then
    fail "accepted: $args"
  fi
done
[ ! -e "$tmp/stage3" ] || fail "a bad argument still wrote files"
echo "arguments ok"

# Uninstall takes away what install put there.
sh "$inst" --stage "$st" --uninstall >/dev/null 2>&1 || fail "uninstall failed"
for f in usr/local/bin/remnascope-agent-awg etc/remnascope/awg.token etc/sudoers.d/remnascope-awg etc/systemd/system/remnascope-awg.service; do
  [ ! -e "$st/$f" ] || fail "still there after uninstall: $f"
done
echo "uninstall ok"
echo OK
