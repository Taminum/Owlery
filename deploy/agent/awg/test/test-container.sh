#!/bin/sh
# Integration test for remnascope-awg-container against a REAL Docker. It fetches Amnezia's server scripts from
# the pinned upstream commit (which also proves the recorded SHA-256 values still match), creates a throwaway
# container, checks that the interface is up and that the snapshot and the management helper work on it, then
# removes it. Needs docker, network access and ~1 minute. It touches only the container it creates.
#
#   sh deploy/agent/awg/test/test-container.sh [container-name] [port] [subnet]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
H="$here/../remnascope-awg-container"
name="${1:-amnezia-awg9}"; port="${2:-53999}"; subnet="${3:-10.77.1.0/24}"
command -v docker >/dev/null || { echo "SKIP: docker is not available"; exit 0; }
docker info >/dev/null 2>&1 || { echo "SKIP: the docker daemon is not reachable"; exit 0; }
DOCKER="${DOCKER:-$(command -v docker)}"; export DOCKER
tmp=$(mktemp -d); trap 'docker rm -f "$name" >/dev/null 2>&1 || true; docker rmi "$name" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }
printf 'MANAGED=""\nENDPOINT_HOST="203.0.113.10"\nDNS="1.1.1.1"\nSENSE=""\n' > "$tmp/conf"
env_() { env MANAGE_CONF="$tmp/conf" LOCKFILE="$tmp/lock" SYSTEMCTL=true FLOCK="${FLOCK:-flock}" "$@"; }

out=$(env_ sh "$H" install "$name" "$port" "$subnet" | head -1)
printf '%s\n' "$out" | grep -q "^RESULT	ok	$name	" || fail "install: $out"
echo "install ok"
docker exec "$name" awg show interfaces | grep -qw awg0 || fail "awg0 is not up"
grep -qx "MANAGED=\"$name\"" "$tmp/conf" || fail "the helper config was not updated"
# Nothing secret is in the output line: only the public key.
printf '%s\n' "$out" | grep -qi "privatekey" && fail "a private key was printed"

snap=$(env_ sh "$here/../remnascope-awg-snapshot")
printf '%s\n' "$snap" | grep -q "^I	$name	awg0	$port	" || fail "the snapshot does not see the container"
printf '%s\n' "$snap" | grep -q "^M	$name" || fail "the container is not marked managed"
echo "snapshot ok"

add=$(env_ sh "$here/../remnascope-awg-manage" add "$name" TestPhone | head -1)
printf '%s\n' "$add" | grep -q "^RESULT	ok	" || fail "add device: $add"
echo "manage ok"

# Backup and move: export the files, remove the container, restore it from them. The server's key and the
# device must be the same afterwards.
pubkey_of() { docker exec "$name" cat /opt/amnezia/awg/wireguard_server_public_key.key | tr -d '
'; }
srv_before=$(pubkey_of)
peer_before=$(docker exec "$name" awg show awg0 peers | head -1)
[ -n "$peer_before" ] || fail "no device to carry over"
env_ sh "$H" export "$name" > "$tmp/backup" || fail "export"
head -1 "$tmp/backup" | grep -q "^RESULT	ok	$name" || fail "export result: $(head -1 "$tmp/backup")"
grep -q "^FILE	awg0.conf	" "$tmp/backup" || fail "export has no config"
echo "export ok"
env_ sh "$H" remove "$name" yes-delete-all-devices | grep -q "^RESULT	ok" || fail "removal before restore"
tail -n +2 "$tmp/backup" | env_ sh "$H" restore "$name" | grep -q "^RESULT	ok	$name	" || fail "restore"
[ "$(pubkey_of)" = "$srv_before" ] || fail "the server key changed in the restore"
docker exec "$name" awg show awg0 peers | grep -qx "$peer_before" || fail "the device is missing after the restore"
echo "restore ok"
# A configuration that would run a command is refused before anything is created.
env_ sh "$H" remove "$name" yes-delete-all-devices >/dev/null
evil=$(printf '[Interface]
PrivateKey = AAAA
Address = 10.77.1.0/24
ListenPort = %s
PostUp = touch /pwned
' "$port" | base64 | tr -d '
')
printf 'FILE	awg0.conf	%s
' "$evil" | env_ sh "$H" restore "$name" | grep -q "bad_config" || fail "a PostUp line was accepted"
docker inspect "$name" >/dev/null 2>&1 && fail "a container was created from a refused configuration"
echo "restore-guard ok"
# Put one back for the checks below.
env_ sh "$H" install "$name" "$port" "$subnet" | grep -q "^RESULT	ok" || fail "install again"

# A second install of the same name, the same port, and a bad confirmation are all refused.
env_ sh "$H" install "$name" "$port" "$subnet" | grep -q "container_exists" || fail "a second install was not refused"
env_ sh "$H" remove "$name" nope | grep -q "not_confirmed" || fail "removal without confirmation"
env_ sh "$H" remove "$name" yes-delete-all-devices | grep -q "^RESULT	ok" || fail "removal"
docker inspect "$name" >/dev/null 2>&1 && fail "the container is still there"
grep -qx 'MANAGED=""' "$tmp/conf" || fail "the helper config still lists it"
echo "remove ok"
echo OK
