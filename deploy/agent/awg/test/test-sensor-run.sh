#!/bin/sh
# remnascope-awg-sensor-run starts the sensor only for allowed containers, only with fixed arguments.
set -u
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
printf 'SENSE="amnezia-awg2 amnezia-awg3"\n' > "$tmp/conf"
export DOCKER="$here/sensor/docker" SENSOR="$here/sensor/sensor" MANAGE_CONF="$tmp/conf"
R="$here/../remnascope-awg-sensor-run"
fail() { echo "FAIL: $1" >&2; exit 1; }
out=$(sh "$R" amnezia-awg2) || fail "allowed container refused"
[ "$out" = "ARGS -pid 4242 -container amnezia-awg2 -iface awg0 -interval 60s -out /run/remnascope-awg/sensor.sock" ] || fail "arguments: $out"
sh "$R" other-container >/dev/null 2>&1 && fail "a container outside SENSE was started"
sh "$R" 'bad;name' >/dev/null 2>&1 && fail "a bad name was accepted"
sh "$R" '../x' >/dev/null 2>&1 && fail "a path was accepted"
sh "$R" >/dev/null 2>&1 && fail "no argument was accepted"
sh "$R" amnezia-awg2 extra >/dev/null 2>&1 && fail "an extra argument was accepted"
printf 'SENSE=""\n' > "$tmp/conf"
sh "$R" amnezia-awg2 >/dev/null 2>&1 && fail "an empty list started a sensor"
echo OK
