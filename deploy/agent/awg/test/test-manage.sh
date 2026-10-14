#!/bin/bash
# Runs remnascope-awg-manage against a sandbox that plays a managed AmneziaWG container, and checks what it does and,
# as importantly, what it refuses to do.
set -u
here=$(cd "$(dirname "$0")" && pwd)
SB=$(mktemp -d)
trap 'rm -rf "$SB"' EXIT
export SANDBOX="$SB" DOCKER="$here/manage/docker" MANAGE_CONF="$SB/awg-manage.conf" LOCKFILE="$SB/lock" FLOCK=true
mkdir -p "$SB/awg" "$SB/bin"
cp "$here/manage/awg" "$SB/bin/awg"
fail() { echo "FAIL: $1" >&2; exit 1; }

PSK='psk0psk0psk0psk0psk0psk0psk0psk0psk0psk0psk='
SPUB='serverpubserverpubserverpubserverpubserverp='
OLD='oldpeeroldpeeroldpeeroldpeeroldpeeroldpeer='   # an existing device the tool must never touch
printf '%s' "$PSK" > "$SB/awg/wireguard_psk.key"
printf '%s' "$SPUB" > "$SB/awg/wireguard_server_public_key.key"
cat > "$SB/awg/awg0.conf" <<EOT
[Interface]
PrivateKey = SERVERSECRETSERVERSECRETSERVERSECRET00000=
Address = 10.8.1.1/24
ListenPort = 55424
Jc = 4
Jmin = 10
Jmax = 50
S1 = 100
I1 = <b 0xdeadbeef>
# MTU = 1371
# DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $OLD
PresharedKey = $PSK
AllowedIPs = 10.8.1.2/32
EOT
printf '%s\t%s\n' "$OLD" "10.8.1.2/32" > "$SB/peers"
printf 'MANAGED="managed-one"\nENDPOINT_HOST="203.0.113.10"\nDNS="1.1.1.1, 1.0.0.1"\n' > "$MANAGE_CONF"

M="$here/../remnascope-awg-manage"
conf_sum() { md5sum "$SB/awg/awg0.conf" | cut -d' ' -f1; }
peers_sum() { md5sum "$SB/peers" | cut -d' ' -f1; }

# --- refusals change nothing
before="$(conf_sum)$(peers_sum)"
refuse() { out=$(sh "$M" "$@" 2>&1); printf '%s\n' "$out" | head -1 | grep -q "RESULT	error	$EXPECT" || fail "expected $EXPECT for: $* -> $out"; [ "$(conf_sum)$(peers_sum)" = "$before" ] || fail "state changed on refusal: $*"; }
EXPECT=not_managed   refuse add other-container "Phone"
EXPECT=bad_container refuse add "bad;container" "Phone"
EXPECT=bad_container refuse add "../x" "Phone"
EXPECT=bad_name      refuse add managed-one 'a;rm -rf /'
EXPECT=bad_name      refuse add managed-one '$(id)'
EXPECT=bad_name      refuse add managed-one ''
EXPECT=bad_name      refuse add managed-one "$(printf 'x%.0s' $(seq 1 41))"
EXPECT=bad_key       refuse revoke managed-one 'not-a-key'
EXPECT=bad_key       refuse revoke managed-one "$(printf 'A%.0s' $(seq 1 43))"
EXPECT=bad_operation refuse delete managed-one "Phone"
EXPECT=bad_arguments refuse add managed-one
EXPECT=not_found     refuse revoke managed-one "$(printf 'B%.0s' $(seq 1 43))="
FAIL_SET=1 EXPECT=apply_failed refuse add managed-one "Phone"

# --- add
out=$(sh "$M" add managed-one "Pixel 8 (Mish)") || fail "add exited non-zero"
first=$(printf '%s\n' "$out" | head -1)
printf '%s\n' "$first" | grep -Eq '^RESULT	ok	[A-Za-z0-9+/]{43}=	10\.8\.1\.3$' || fail "add result line: $first"
pub1=$(printf '%s' "$first" | cut -f3)
printf '%s\n' "$out" | grep -qx 'Address = 10.8.1.3/32' || fail "client address"
printf '%s\n' "$out" | grep -qx 'DNS = 1.1.1.1, 1.0.0.1' || fail "client dns"
printf '%s\n' "$out" | grep -qx 'MTU = 1371' || fail "client mtu"
printf '%s\n' "$out" | grep -qx 'Jc = 4' || fail "obfuscation parameter missing"
printf '%s\n' "$out" | grep -qx 'I1 = <b 0xdeadbeef>' || fail "I1 missing"
printf '%s\n' "$out" | grep -qx "PublicKey = $SPUB" || fail "server public key"
printf '%s\n' "$out" | grep -qx "PresharedKey = $PSK" || fail "psk"
printf '%s\n' "$out" | grep -qx 'Endpoint = 203.0.113.10:55424' || fail "endpoint"
printf '%s\n' "$out" | grep -q '^PrivateKey = ' || fail "client private key missing"
printf '%s\n' "$out" | grep -q 'SERVERSECRET' && fail "the SERVER private key leaked into a client config"
printf '%s\n' "$out" | grep -q '^ListenPort' && fail "server listen port leaked into client config"
grep -qxF "PublicKey = $pub1" "$SB/awg/awg0.conf" || fail "peer not persisted"
grep -qxF "# remnascope: Pixel 8 (Mish)" "$SB/awg/awg0.conf" || fail "name comment missing"
grep -qxF "AllowedIPs = 10.8.1.3/32" "$SB/awg/awg0.conf" || fail "allowed ips not persisted"
grep -qF "$pub1" "$SB/peers" || fail "peer not applied live"
grep -qxF "PublicKey = $OLD" "$SB/awg/awg0.conf" || fail "existing peer disturbed"
ls "$SB/awg" | grep -q '^awg0.conf.bak.remnascope.' || fail "no backup before the change"
grep -q "PRIVKEY" "$SB/awg/awg0.conf" && fail "client private key was stored on the server"
client_priv=$(printf '%s\n' "$out" | sed -n 's/^PrivateKey = //p')
grep -qF "$client_priv" "$SB/awg/awg0.conf" "$SB/peers" && fail "client private key found in server state"

# --- a second add never reuses an address
out2=$(sh "$M" add managed-one "Laptop") || fail "second add"
printf '%s\n' "$out2" | head -1 | grep -q '	10\.8\.1\.4$' || fail "second add address: $(printf '%s\n' "$out2" | head -1)"
pub2=$(printf '%s\n' "$out2" | head -1 | cut -f3)

# --- revoke removes only that device
sh "$M" revoke managed-one "$pub1" | head -1 | grep -q "RESULT	ok	$pub1" || fail "revoke result"
grep -qF "$pub1" "$SB/awg/awg0.conf" && fail "revoked peer still in config"
grep -qF "$pub1" "$SB/peers" && fail "revoked peer still live"
grep -qF "Pixel 8" "$SB/awg/awg0.conf" && fail "revoked device's comment remained"
grep -qxF "PublicKey = $OLD" "$SB/awg/awg0.conf" || fail "revoke removed the wrong device (old)"
grep -qxF "PublicKey = $pub2" "$SB/awg/awg0.conf" || fail "revoke removed the wrong device (second)"
grep -q '^\[Interface\]' "$SB/awg/awg0.conf" && grep -qx 'PrivateKey = SERVERSECRETSERVERSECRETSERVERSECRET00000=' "$SB/awg/awg0.conf" || fail "interface section damaged"
# the freed address can be given again
out3=$(sh "$M" add managed-one "Again") || fail "third add"
printf '%s\n' "$out3" | head -1 | grep -q '	10\.8\.1\.3$' || fail "freed address not reused: $(printf '%s\n' "$out3" | head -1)"
# revoking twice is refused
sh "$M" revoke managed-one "$pub1" | head -1 | grep -q 'RESULT	error	not_found' || fail "second revoke of the same device"
echo OK
