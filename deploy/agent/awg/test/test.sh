#!/bin/sh
# Runs remnascope-awg-snapshot against a fake docker and checks the output: the right facts, and no secret.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
mc=$(mktemp); printf 'MANAGED="amnezia-awg2"
' > "$mc"
out=$(DOCKER="$here/docker" CONTAINERS="amnezia-awg2" MANAGE_CONF="$mc" sh "$here/../remnascope-awg-snapshot"); rm -f "$mc"
printf '%s\n' "$out"
fail() { echo "FAIL: $1" >&2; exit 1; }
has() { printf '%s\n' "$out" | grep -qxF "$(printf "$1")" || fail "$2"; }
printf '%s\n' "$out" | grep -q "SECRET" && fail "a secret was printed"
has 'I\tamnezia-awg2\tawg0\t49587\tH1,H2,H3,H4,Jc,Jmax,Jmin,S1,S2,S3,S4\t1791353419' "instance line"
has 'P\tamnezia-awg2\tAAAA1111111111111111111111111111111111111=\t1760400000\t1000\t2000\t10.8.1.2/32' "peer line A"
has 'P\tamnezia-awg2\tBBBB2222222222222222222222222222222222222=\t0\t0\t0\t10.8.1.18/32,fd00::2/128' "peer line B"
has 'N\tamnezia-awg2\tAAAA1111111111111111111111111111111111111=\tRouterOne' "name A"
has 'N\tamnezia-awg2\tBBBB2222222222222222222222222222222222222=\tLaptop2' "name B"
has 'T	amnezia-awg2	1759400700' "table time"
has 'L	amnezia-awg2	AAAA1111111111111111111111111111111111111=	106.76 GiB	49.27 GiB	4d, 3h, 14m, 18s ago	2026-04-03T10:01:05.979470' "legacy line"
has 'M	amnezia-awg2' "managed marker"
echo "OK"
