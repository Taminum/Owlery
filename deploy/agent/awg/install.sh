#!/bin/sh
# remnascope-awg-install: puts the Owlery AmneziaWG agent on a host that already runs Amnezia containers.
#
#   sudo sh install.sh --server wss://scope.example.com/ingest/v1 --token-file /path/to/token \
#        --endpoint-host 203.0.113.10 --managed "amnezia-awg2 amnezia-awg3"
#
# It does what docs/AWG_COLLECTOR.md lists as separate steps, in one pass, and nothing else:
#   * downloads the release files (agent, traffic sensor, helper scripts) and checks them against SHA256SUMS;
#   * creates the system user "remnascope" (no login), the token file (root:remnascope, 0640) and the helper
#     configuration /etc/remnascope/awg-manage.conf;
#   * installs the read-only snapshot helper, the management helper and the traffic sensor under
#     /usr/local/sbin, each behind one exact sudoers rule;
#   * installs and starts the agent service and one sensor service per container.
# It does not touch Docker, the containers, their configs or any existing Owlery log agent.
#
# Options
#   --server URL         the ingest address of Owlery (wss://.../ingest/v1)            [required]
#   --token TOKEN | --token-file FILE | env REMNASCOPE_TOKEN                              [required once]
#   --endpoint-host H    the address clients connect to (goes into client configs)         [required]
#   --managed "a b"      containers whose devices Owlery may add and revoke            [default: none]
#   --sense "a b"        containers whose traffic the sensor watches                       [default: --managed]
#   --dns "1.1.1.1, ..." DNS written into new client configs                               [default 1.1.1.1, 1.0.0.1]
#   --container-admin    also install the helper that can CREATE and REMOVE AmneziaWG containers
#                        (remnascope-awg-container) behind its own sudoers rule. Off by default.
#   --version TAG        release to install                                               [default: latest]
#   --from DIR           use files already in DIR instead of downloading (agent, sensor, tar, SHA256SUMS)
#   --stage DIR          write everything under DIR and run no systemctl/useradd (for tests and review)
#   --uninstall          remove what this script installed (devices already added stay on the server)
#   --dry-run            print what would be done
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin

SERVER="" TOKEN="${REMNASCOPE_TOKEN:-}" TOKEN_FILE="" ENDPOINT="" MANAGED="" SENSE="" DNS="1.1.1.1, 1.0.0.1"
VERSION="latest" FROM="" STAGE="" UNINSTALL=0 DRY=0 CONTAINER_ADMIN=0
BASE_URL="${REMNASCOPE_RELEASE_URL:-https://github.com/Taminum/Owlery/releases}"

die() { echo "install: $*" >&2; exit 1; }
say() { echo "install: $*"; }
need_val() { [ $# -ge 2 ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server) need_val "$@"; SERVER="$2"; shift 2 ;;
    --token) need_val "$@"; TOKEN="$2"; shift 2 ;;
    --token-file) need_val "$@"; TOKEN_FILE="$2"; shift 2 ;;
    --endpoint-host) need_val "$@"; ENDPOINT="$2"; shift 2 ;;
    --managed) need_val "$@"; MANAGED="$2"; shift 2 ;;
    --sense) need_val "$@"; SENSE="$2"; shift 2 ;;
    --dns) need_val "$@"; DNS="$2"; shift 2 ;;
    --version) need_val "$@"; VERSION="$2"; shift 2 ;;
    --from) need_val "$@"; FROM="$2"; shift 2 ;;
    --stage) need_val "$@"; STAGE="$2"; shift 2 ;;
    --container-admin) CONTAINER_ADMIN=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

# --- validation: everything that ends up in a file or a command line is checked first ----------------------
word_ok() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$'; }
list_ok() { for w in $1; do word_ok "$w" || return 1; done; }

if [ "$UNINSTALL" -eq 0 ]; then
  printf '%s' "$SERVER" | grep -Eq '^wss?://[A-Za-z0-9.-]+(:[0-9]+)?/ingest/v1$' || die "--server must look like wss://host/ingest/v1"
  printf '%s' "$ENDPOINT" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9.:-]{0,100}$' || die "--endpoint-host is required (an address or name clients connect to)"
  printf '%s' "$DNS" | grep -Eq '^[0-9A-Fa-f.:, ]{1,100}$' || die "--dns must be addresses separated by commas"
  [ -n "$SENSE" ] || SENSE="$MANAGED"
  list_ok "$MANAGED" || die "--managed: bad container name"
  list_ok "$SENSE" || die "--sense: bad container name"
  printf '%s' "$VERSION" | grep -Eq '^(latest|v[0-9][A-Za-z0-9._-]{0,30})$' || die "--version must be latest or a tag like v0.3.0"
  if [ -n "$TOKEN_FILE" ]; then
    [ -r "$TOKEN_FILE" ] || die "cannot read $TOKEN_FILE"
    TOKEN=$(tr -d '\r\n' < "$TOKEN_FILE")
  fi
fi

R="${STAGE:-}"                     # every path below is under $R
ETC="$R/etc/remnascope"
SBIN="$R/usr/local/sbin"
BIN="$R/usr/local/bin"
UNITS="$R/etc/systemd/system"
SUDOERS="$R/etc/sudoers.d"
CONF="$ETC/awg-manage.conf"

run() { if [ "$DRY" -eq 1 ]; then echo "+ $*"; else "$@"; fi; }
sysctl_run() { [ -n "$STAGE" ] && return 0; run "$@"; }

# --- uninstall ---------------------------------------------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
  [ -n "$STAGE" ] || [ "$(id -u)" -eq 0 ] || die "run as root"
  if [ -f "$CONF" ]; then
    for c in $(sed -n 's/^SENSE="\(.*\)"$/\1/p' "$CONF" | head -1); do
      sysctl_run systemctl disable --now "remnascope-awg-sensor@$c" || true
    done
  fi
  sysctl_run systemctl disable --now remnascope-awg-sensors.path || true
  sysctl_run systemctl disable --now remnascope-awg || true
  run rm -rf "$UNITS/remnascope-awg.service" "$UNITS/remnascope-awg.service.d" "$UNITS/remnascope-awg-sensor@.service" \
    "$SUDOERS/remnascope-awg" "$SUDOERS/remnascope-awg-manage" "$SUDOERS/remnascope-awg-container" "$SBIN/remnascope-awg-container" "$SBIN/remnascope-awg-sensors-sync" "$UNITS/remnascope-awg-sensors.path" "$UNITS/remnascope-awg-sensors.service" "$BIN/remnascope-agent-awg" \
    "$SBIN/remnascope-awg-snapshot" "$SBIN/remnascope-awg-manage" "$SBIN/remnascope-awg-sensor" "$SBIN/remnascope-awg-sensor-run" \
    "$ETC/awg.token" "$CONF" "$R/var/lib/remnascope-awg"
  sysctl_run systemctl daemon-reload
  say "removed. Devices added through Owlery remain on the server until revoked; revoke the agent in Owlery too."
  exit 0
fi

[ -n "$TOKEN" ] || [ -f "$ETC/awg.token" ] || die "a token is required the first time (--token-file)"
if [ -z "$STAGE" ]; then
  [ "$(id -u)" -eq 0 ] || die "run as root"
  command -v systemctl >/dev/null || die "systemd is required"
  command -v docker >/dev/null || die "docker is required"
  command -v visudo >/dev/null || die "visudo is required"
  command -v sha256sum >/dev/null || die "sha256sum is required"
fi

# --- the files ---------------------------------------------------------------------------------------------
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) die "unsupported architecture $(uname -m)" ;; esac
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
A_AGENT="remnascope-agent-linux-$ARCH"; A_SENSOR="remnascope-awg-sensor-linux-$ARCH"; A_TAR="remnascope-deploy-files.tar.gz"

if [ -n "$FROM" ]; then
  for f in "$A_AGENT" "$A_SENSOR" "$A_TAR" SHA256SUMS; do
    [ -f "$FROM/$f" ] || die "$FROM/$f is missing"
    cp "$FROM/$f" "$WORK/$f"
  done
else
  if [ "$VERSION" = latest ]; then URL="$BASE_URL/latest/download"; else URL="$BASE_URL/download/$VERSION"; fi
  fetch() {
    if command -v curl >/dev/null; then curl -fsSL --retry 3 -o "$WORK/$1" "$URL/$1"
    elif command -v wget >/dev/null; then wget -q -O "$WORK/$1" "$URL/$1"
    else die "curl or wget is required"; fi
  }
  say "downloading release files ($VERSION)"
  if [ "$DRY" -eq 1 ]; then
    for f in "$A_AGENT" "$A_SENSOR" "$A_TAR" SHA256SUMS; do echo "+ fetch $URL/$f"; done
    exit 0
  fi
  for f in "$A_AGENT" "$A_SENSOR" "$A_TAR" SHA256SUMS; do fetch "$f"; done
fi

# Every file must be listed in SHA256SUMS and match it.
( cd "$WORK" && for f in "$A_AGENT" "$A_SENSOR" "$A_TAR"; do
    awk -v f="$f" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 "  " n }' SHA256SUMS | sha256sum -c - >/dev/null 2>&1       || { echo "install: checksum mismatch or missing for $f" >&2; exit 1; }
  done ) || exit 1
say "files verified against SHA256SUMS"
tar -xzf "$WORK/$A_TAR" -C "$WORK" deploy/agent/awg
SRC="$WORK/deploy/agent/awg"
REQUIRED="remnascope-awg-snapshot remnascope-awg-manage remnascope-awg-sensor-run remnascope-awg.service remnascope-awg-sensor@.service"
[ "$CONTAINER_ADMIN" -eq 1 ] && REQUIRED="$REQUIRED remnascope-awg-container remnascope-awg-sensors-sync remnascope-awg-sensors.service remnascope-awg-sensors.path"
for f in $REQUIRED; do
  [ -f "$SRC/$f" ] || die "the release does not contain $f"
done

# --- install -----------------------------------------------------------------------------------------------
if [ -z "$STAGE" ] && ! id remnascope >/dev/null 2>&1; then
  run useradd --system --no-create-home --shell /usr/sbin/nologin remnascope
fi
run install -d -m 0755 "$ETC" "$SBIN" "$BIN" "$UNITS" "$SUDOERS"
run install -m 0755 "$WORK/$A_AGENT" "$BIN/remnascope-agent-awg"
run install -m 0755 "$WORK/$A_SENSOR" "$SBIN/remnascope-awg-sensor"
for f in remnascope-awg-snapshot remnascope-awg-manage remnascope-awg-sensor-run; do
  run install -m 0755 "$SRC/$f" "$SBIN/$f"
done
if [ "$CONTAINER_ADMIN" -eq 1 ]; then
  run install -m 0755 "$SRC/remnascope-awg-container" "$SBIN/remnascope-awg-container"
  printf '%s\n' 'remnascope ALL=(root) NOPASSWD: /usr/local/sbin/remnascope-awg-container' > "$SUDOERS/remnascope-awg-container"
  chmod 0440 "$SUDOERS/remnascope-awg-container"
  [ -n "$STAGE" ] || visudo -cf "$SUDOERS/remnascope-awg-container" >/dev/null || { rm -f "$SUDOERS/remnascope-awg-container"; die "sudoers check failed"; }
fi
run install -m 0644 "$SRC/remnascope-awg-sensor@.service" "$UNITS/remnascope-awg-sensor@.service"
if [ "$CONTAINER_ADMIN" -eq 1 ]; then
  run install -m 0755 "$SRC/remnascope-awg-sensors-sync" "$SBIN/remnascope-awg-sensors-sync"
  run install -m 0644 "$SRC/remnascope-awg-sensors.service" "$UNITS/remnascope-awg-sensors.service"
  run install -m 0644 "$SRC/remnascope-awg-sensors.path" "$UNITS/remnascope-awg-sensors.path"
fi

if [ -n "$TOKEN" ]; then
  umask 077
  printf '%s\n' "$TOKEN" > "$ETC/awg.token"
  [ -n "$STAGE" ] || chown root:remnascope "$ETC/awg.token"
  chmod 0640 "$ETC/awg.token"
  umask 022
fi

{
  printf 'MANAGED="%s"\n' "$MANAGED"
  printf 'ENDPOINT_HOST="%s"\n' "$ENDPOINT"
  printf 'DNS="%s"\n' "$DNS"
  printf 'SENSE="%s"\n' "$SENSE"
} > "$CONF"
chmod 0644 "$CONF"

printf '%s\n' 'remnascope ALL=(root) NOPASSWD: /usr/local/sbin/remnascope-awg-snapshot' > "$SUDOERS/remnascope-awg"
printf '%s\n' 'remnascope ALL=(root) NOPASSWD: /usr/local/sbin/remnascope-awg-manage' > "$SUDOERS/remnascope-awg-manage"
chmod 0440 "$SUDOERS/remnascope-awg" "$SUDOERS/remnascope-awg-manage"
if [ -z "$STAGE" ]; then
  visudo -cf "$SUDOERS/remnascope-awg" >/dev/null || { rm -f "$SUDOERS/remnascope-awg" "$SUDOERS/remnascope-awg-manage"; die "sudoers check failed"; }
  visudo -cf "$SUDOERS/remnascope-awg-manage" >/dev/null || { rm -f "$SUDOERS/remnascope-awg" "$SUDOERS/remnascope-awg-manage"; die "sudoers check failed"; }
fi

# The service file, with this server's address and the list of containers the snapshot helper may look at.
SNAP_CONTAINERS="$(printf '%s %s' "$MANAGED" "$SENSE" | tr ' ' '\n' | grep -v '^$' | sort -u | paste -sd' ' -)"
sed -e "s#wss://scope.example.com/ingest/v1#$SERVER#" "$SRC/remnascope-awg.service" > "$UNITS/remnascope-awg.service"
run install -d "$UNITS/remnascope-awg.service.d"
{
  echo '[Service]'
  echo 'Environment="REMNASCOPE_AWG_MANAGE=/usr/bin/sudo -n /usr/local/sbin/remnascope-awg-manage"'
  echo 'RuntimeDirectory=remnascope-awg'
  echo 'RuntimeDirectoryMode=0750'
  echo 'Environment="REMNASCOPE_AWG_SENSOR_SOCKET=/run/remnascope-awg/sensor.sock"'
  printf 'Environment="REMNASCOPE_AWG_SENSOR_CONTAINERS=%s"\n' "$(printf '%s' "$SENSE" | tr ' ' ',')"
  if [ "$CONTAINER_ADMIN" -eq 1 ]; then
    echo 'Environment="REMNASCOPE_AWG_CONTAINER=/usr/bin/sudo -n /usr/local/sbin/remnascope-awg-container"'
    # The container helper (root, inside the agent's sandbox) records containers in the config directory.
    echo 'ReadWritePaths=/etc/remnascope'
  fi
} > "$UNITS/remnascope-awg.service.d/10-remnascope.conf"
chmod 0644 "$UNITS/remnascope-awg.service" "$UNITS/remnascope-awg.service.d/10-remnascope.conf"
# The snapshot helper reads CONTAINERS from its environment; the agent's sudo rule runs it as is, so the
# container list is also written where the helper looks for it: MANAGED and SENSE above, or its own default.
[ -n "$SNAP_CONTAINERS" ] && printf 'CONTAINERS="%s"\n' "$SNAP_CONTAINERS" >> "$CONF"

sysctl_run systemctl daemon-reload
sysctl_run systemctl enable --now remnascope-awg
for c in $SENSE; do sysctl_run systemctl enable --now "remnascope-awg-sensor@$c"; done
[ "$CONTAINER_ADMIN" -eq 1 ] && sysctl_run systemctl enable --now remnascope-awg-sensors.path

if [ -z "$STAGE" ]; then
  sleep 3
  say "agent: $(systemctl is-active remnascope-awg)"
  for c in $SENSE; do say "sensor $c: $(systemctl is-active "remnascope-awg-sensor@$c")"; done
  say "check: sudo -u remnascope sudo -n /usr/local/sbin/remnascope-awg-snapshot | cut -c1-100"
fi
say "done"
