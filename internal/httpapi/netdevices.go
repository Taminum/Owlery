package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/keenetic"
	"github.com/Taminum/Owlery/internal/netdev"
	"github.com/Taminum/Owlery/internal/store"
)

// NetIngestPath is where network devices post what they know.
const NetIngestPath = "/ingest/net/v1"

// routerScript is the RouterOS script that posts a router's state: the statistics and the ports in one piece, the clients in pieces of
// twenty (RouterOS cuts strings that grow long). It uses only commands that RouterOS 6 and 7 both have.
const routerScript = `:local url "https://@HOST@@PATH@"
:local hdr "Authorization: Bearer @TOKEN@"
:local nl "\n"
:local b ""
:set b ("board=" . [/system resource get board-name] . $nl)
:set b ($b . "version=" . [/system resource get version] . $nl)
:set b ($b . "uptime=" . [/system resource get uptime] . $nl)
:set b ($b . "cpu=" . [/system resource get cpu-load] . $nl)
:set b ($b . "mem_free=" . [/system resource get free-memory] . $nl)
:set b ($b . "mem_total=" . [/system resource get total-memory] . $nl)
:local t ""
:do { :local f [:parse "/system health get temperature"]; :set t [$f] } on-error={ :do { :local f2 [:parse "/system health get [find name=temperature] value"]; :set t [$f2] } on-error={} }
:if ([:len $t] > 0) do={ :set b ($b . "temp=" . $t . $nl) }
:foreach i in=[/interface find] do={ :set b ($b . "if=" . [/interface get $i name] . "," . [/interface get $i rx-byte] . "," . [/interface get $i tx-byte] . "," . [/interface get $i running] . $nl) }
/tool fetch url=$url http-method=post http-header-field=$hdr http-data=$b keep-result=no
:do {
  :local cnt [:len [/ip firewall connection find]]
  :set b ("conn=" . $cnt . $nl)
  :do { :set b ($b . "conn_max=" . [/ip firewall connection tracking get max-entries] . $nl) } on-error={}
  :if ($cnt <= 5000) do={
    :local src [:toarray ""]
    :foreach c in=[/ip firewall connection find] do={
      :local a [/ip firewall connection get $c src-address]
      :local p [:find $a ":"]
      :local ip $a
      :if ([:typeof $p] = "num") do={ :set ip [:pick $a 0 $p] }
      :local cur ($src->$ip)
      :if ([:typeof $cur] != "num") do={ :set cur 0 }
      :set ($src->$ip) ($cur + 1)
    }
    :for r from=1 to=8 do={
      :local bk ""
      :local bv 0
      :foreach kk,vv in=$src do={ :if ($vv > $bv) do={ :set bk $kk; :set bv $vv } }
      :if ($bv > 0) do={ :set b ($b . "top=" . $bk . "," . $bv . $nl); :set ($src->$bk) 0 }
    }
  }
  /tool fetch url=$url http-method=post http-header-field=$hdr http-data=$b keep-result=no
} on-error={}
:do {
  :set b ("reset_nat=1" . $nl)
  :local k 0
  :foreach r in=[/ip firewall nat find where disabled=no] do={
    :if ($k < 20) do={
      :local dp ""
      :local ta ""
      :local tp ""
      :local cm ""
      :do { :set dp [/ip firewall nat get $r dst-port] } on-error={}
      :do { :set ta [/ip firewall nat get $r to-addresses] } on-error={}
      :do { :set tp [/ip firewall nat get $r to-ports] } on-error={}
      :do { :set cm [/ip firewall nat get $r comment] } on-error={}
      :set b ($b . "nat=" . [/ip firewall nat get $r chain] . "," . [/ip firewall nat get $r action] . "," . [/ip firewall nat get $r packets] . "," . [/ip firewall nat get $r bytes] . "," . $dp . "," . $ta . "," . $tp . "," . $cm . $nl)
    }
    :set k ($k + 1)
  }
  /tool fetch url=$url http-method=post http-header-field=$hdr http-data=$b keep-result=no
} on-error={}
:set b ("reset_clients=1" . $nl)
:local n 0
:foreach l in=[/ip dhcp-server lease find where status=bound] do={
  :local hn ""
  :do { :set hn [/ip dhcp-server lease get $l host-name] } on-error={}
  :set b ($b . "client=" . [/ip dhcp-server lease get $l address] . "," . [/ip dhcp-server lease get $l mac-address] . "," . $hn . $nl)
  :set n ($n + 1)
  :if ($n = 20) do={
    /tool fetch url=$url http-method=post http-header-field=$hdr http-data=$b keep-result=no
    :set b ""
    :set n 0
  }
}
:if ([:len $b] > 0) do={ /tool fetch url=$url http-method=post http-header-field=$hdr http-data=$b keep-result=no }
:do {
  :set b ("reset_access=1" . $nl)
  :foreach r in=[/ip firewall filter find where comment~"^owlery-block "] do={
    :set b ($b . "blocked=" . [:pick [/ip firewall filter get $r comment] 13 30] . $nl)
  }
  :foreach l in=[/ip dhcp-server lease find where dynamic=no] do={
    :local mc ""
    :local ad ""
    :do { :set mc [/ip dhcp-server lease get $l mac-address] } on-error={}
    :do { :set ad [/ip dhcp-server lease get $l address] } on-error={}
    :if ([:len $mc] = 17 && [:len $ad] > 0) do={ :set b ($b . "reserved=" . $mc . "," . $ad . $nl) }
  }
  /tool fetch url=$url http-method=post http-header-field=$hdr http-data=$b keep-result=no
} on-error={}
:local cu "https://@HOST@@CPATH@"
:local macre "^[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]\$"
:for q from=1 to=5 do={
  :do {
    :local res [/tool fetch url=$cu http-header-field=$hdr output=user as-value]
    :local cmd ($res->"data")
    :if ([:len $cmd] > 0) do={
      :local p1 [:find $cmd "|"]
      :local cid [:pick $cmd 0 $p1]
      :local rest [:pick $cmd ($p1 + 1) [:len $cmd]]
      :local p2 [:find $rest "|"]
      :local kind [:pick $rest 0 $p2]
      :set rest [:pick $rest ($p2 + 1) [:len $rest]]
      :local p3 [:find $rest "|"]
      :local a1 [:pick $rest 0 $p3]
      :local a2 [:pick $rest ($p3 + 1) [:len $rest]]
      :local ok false
      :local why ""
      :do {
        :if ($kind = "reboot") do={ /system reboot }
        :if ($kind = "block" || $kind = "unblock" || $kind = "reserve" || $kind = "unreserve") do={
          :if ($a1 ~ $macre) do={
            :if ($kind = "block") do={
              :if ([:len [/ip firewall filter find where comment=("owlery-block " . $a1)]] = 0) do={
                /ip firewall filter add chain=forward src-mac-address=$a1 action=drop comment=("owlery-block " . $a1) place-before=0
              }
              :set ok true
            }
            :if ($kind = "unblock") do={
              /ip firewall filter remove [find where comment=("owlery-block " . $a1)]
              :set ok true
            }
            :if ($kind = "reserve") do={
              /ip dhcp-server lease make-static [find where mac-address=$a1 and dynamic=yes]
              :if ([:len [/ip dhcp-server lease find where mac-address=$a1 and dynamic=no]] > 0) do={ :set ok true } else={ :set why "no lease" }
            }
            :if ($kind = "unreserve") do={
              /ip dhcp-server lease remove [find where mac-address=$a1 and dynamic=no]
              :set ok true
            }
          } else={ :set why "bad address" }
        }
      } on-error={ :set ok false; :set why "error" }
      :if ($kind != "reboot") do={
        :local ans ("ack=" . $cid . ",ok")
        :if (!$ok) do={ :set ans ("ack=" . $cid . ",fail," . $why) }
        /tool fetch url=$cu http-method=post http-header-field=$hdr http-data=$ans keep-result=no
      }
    }
  } on-error={}
}
`

func buildRouterScript(host, token string) string {
	return strings.NewReplacer("@HOST@", host, "@PATH@", NetIngestPath, "@CPATH@", NetCommandsPath, "@TOKEN@", token).Replace(routerScript)
}

// openwrtInstall is what the owner pastes into an SSH session on an OpenWrt router: it writes the reporting script, adds it to cron
// and runs it once. The script only reads /proc, /sys, uci and the DHCP leases, and posts the same lines a MikroTik does.
const openwrtInstall = `cat > /usr/bin/owlery-report.sh <<'OWL_EOF'
#!/bin/sh
URL="https://@HOST@@PATH@"
TOKEN="@TOKEN@"
f=/tmp/owlery-report.$$
post() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 20 -X POST -H "Authorization: Bearer $TOKEN" --data-binary @"$1" "$URL" >/dev/null
  else
    wget -q -O /dev/null --header="Authorization: Bearer $TOKEN" --post-file="$1" "$URL"
  fi
}
cpu_line() { awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat; }
{
  echo "board=$(tr -d '\r\n' < /tmp/sysinfo/model 2>/dev/null)"
  . /etc/openwrt_release 2>/dev/null
  echo "version=OpenWrt $DISTRIB_RELEASE"
  up=$(cut -d. -f1 /proc/uptime)
  printf 'uptime=%dd%02d:%02d:%02d\n' $((up/86400)) $((up%86400/3600)) $((up%3600/60)) $((up%60))
  set -- $(cpu_line); t1=$1; i1=$2
  sleep 1
  set -- $(cpu_line); dt=$(($1-t1)); di=$(($2-i1))
  if [ "$dt" -gt 0 ]; then echo "cpu=$(( (dt-di)*100/dt ))"; else echo "cpu=0"; fi
  set -- $(awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} /^MemFree:/{f=$2} END{if(a=="")a=f; print t, a}' /proc/meminfo)
  echo "mem_total=$(($1*1024))"
  echo "mem_free=$(($2*1024))"
  for z in /sys/class/thermal/thermal_zone*/temp; do
    if [ -r "$z" ]; then v=$(cat "$z" 2>/dev/null); echo "temp=$((v/1000))"; break; fi
  done
  tail -n +3 /proc/net/dev | while read -r l; do
    n=$(echo "${l%%:*}")
    set -- ${l#*:}
    case "$n" in ifb*|gre*|ip6*|sit*|erspan*|teql*|dummy*|bonding*) continue;; esac
    c=false
    if [ "$n" = lo ] || [ "$(cat /sys/class/net/$n/carrier 2>/dev/null)" = 1 ]; then c=true; fi
    echo "if=$n,$1,$9,$c"
  done
  cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
  if [ -n "$cc" ]; then
    echo "conn=$cc"
    echo "conn_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
    if [ "$cc" -le 5000 ] && [ -r /proc/net/nf_conntrack ]; then
      awk '{for(i=1;i<=NF;i++) if ($i ~ /^src=/) {print substr($i,5); break}}' /proc/net/nf_conntrack | sort | uniq -c | sort -rn | head -8 | while read -r n ip; do echo "top=$ip,$n"; done
    fi
  fi
  echo "reset_nat=1"
  g() { uci -q get "firewall.@redirect[$i].$1" | tr -d '\r\n,'; }
  i=0
  while uci -q get "firewall.@redirect[$i]" >/dev/null 2>&1; do
    if [ "$(uci -q get "firewall.@redirect[$i].enabled")" != 0 ]; then
      act=dst-nat
      [ "$(uci -q get "firewall.@redirect[$i].target")" = SNAT ] && act=src-nat
      echo "nat=dstnat,$act,-,-,$(g src_dport),$(g dest_ip),$(g dest_port),$(g name)"
    fi
    i=$((i+1))
  done
  j=0
  while uci -q get "firewall.@zone[$j]" >/dev/null 2>&1; do
    if [ "$(uci -q get "firewall.@zone[$j].masq")" = 1 ]; then
      echo "nat=srcnat,masquerade,-,-,,,,zone $(uci -q get "firewall.@zone[$j].name" | tr -d '\r\n,')"
    fi
    j=$((j+1))
  done
  echo "reset_access=1"
  i=0
  while uci -q get "firewall.@rule[$i]" >/dev/null 2>&1; do
    case "$(uci -q get "firewall.@rule[$i].name")" in owlery-block-*) echo "blocked=$(uci -q get "firewall.@rule[$i].src_mac" | tr -d '\r\n,')";; esac
    i=$((i+1))
  done
  i=0
  while uci -q get "dhcp.@host[$i]" >/dev/null 2>&1; do
    echo "reserved=$(uci -q get "dhcp.@host[$i].mac" | tr -d '\r\n,'),$(uci -q get "dhcp.@host[$i].ip" | tr -d '\r\n,')"
    i=$((i+1))
  done
  echo "reset_clients=1"
  if [ -r /tmp/dhcp.leases ]; then
    while read -r exp mac ip host rest; do
      [ "$host" = "*" ] && host=""
      echo "client=$ip,$mac,$(echo "$host" | tr -d '\r\n,')"
    done < /tmp/dhcp.leases
  fi
} > "$f"
post "$f"; rc=$?
rm -f "$f"
[ "$rc" = 0 ] || logger -t owlery "report was not sent (curl or wget with https is needed)"
# What the panel asks for: a few things that are built in below and nothing else, one at a time, each answered.
CU="https://@HOST@@CPATH@"
ask() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 20 -H "Authorization: Bearer $TOKEN" "$CU"
  else
    wget -q -O - --header="Authorization: Bearer $TOKEN" "$CU"
  fi
}
answer() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 20 -X POST -H "Authorization: Bearer $TOKEN" --data "$1" "$CU" >/dev/null
  else
    wget -q -O /dev/null --header="Authorization: Bearer $TOKEN" --post-data="$1" "$CU"
  fi
}
upper() { echo "$1" | tr 'a-z' 'A-Z'; }
ismac() { echo "$1" | grep -Eq '^([0-9A-F]{2}:){5}[0-9A-F]{2}$'; }
isip() { echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; }
drop_rules() {
  while :; do
    idx=""; j=0
    while uci -q get "firewall.@rule[$j]" >/dev/null 2>&1; do
      if [ "$(uci -q get "firewall.@rule[$j].name")" = "owlery-block-$1" ]; then idx=$j; break; fi
      j=$((j+1))
    done
    [ -n "$idx" ] || break
    uci delete "firewall.@rule[$idx]"
  done
}
drop_hosts() {
  while :; do
    idx=""; j=0
    while uci -q get "dhcp.@host[$j]" >/dev/null 2>&1; do
      if [ "$(upper "$(uci -q get "dhcp.@host[$j].mac")")" = "$1" ]; then idx=$j; break; fi
      j=$((j+1))
    done
    [ -n "$idx" ] || break
    uci delete "dhcp.@host[$idx]"
  done
}
n=0
while [ "$n" -lt 5 ]; do
  n=$((n+1))
  line=$(ask 2>/dev/null) || break
  [ -n "$line" ] || break
  id=${line%%|*}; rest=${line#*|}; kind=${rest%%|*}; rest=${rest#*|}; a1=${rest%%|*}; a2=${rest#*|}
  ok=0; why=""
  case "$kind" in
    reboot) ( sleep 3; reboot ) >/dev/null 2>&1 & continue ;;
    block|unblock|reserve|unreserve)
      if ! ismac "$a1"; then why="bad address"; else
        case "$kind" in
          block)
            drop_rules "$a1"
            s=$(uci add firewall rule)
            uci set "firewall.$s.name=owlery-block-$a1"; uci set "firewall.$s.src=lan"; uci set "firewall.$s.src_mac=$a1"
            uci set "firewall.$s.dest=*"; uci set "firewall.$s.target=DROP"
            uci commit firewall && /etc/init.d/firewall reload >/dev/null 2>&1 && ok=1 ;;
          unblock)
            drop_rules "$a1"
            uci commit firewall && /etc/init.d/firewall reload >/dev/null 2>&1 && ok=1 ;;
          reserve)
            if ! isip "$a2"; then why="bad address"; else
              drop_hosts "$a1"
              s=$(uci add dhcp host)
              uci set "dhcp.$s.mac=$a1"; uci set "dhcp.$s.ip=$a2"
              uci commit dhcp && /etc/init.d/dnsmasq reload >/dev/null 2>&1 && ok=1
            fi ;;
          unreserve)
            drop_hosts "$a1"
            uci commit dhcp && /etc/init.d/dnsmasq reload >/dev/null 2>&1 && ok=1 ;;
        esac
      fi ;;
    *) why="unknown" ;;
  esac
  if [ "$ok" = 1 ]; then answer "ack=$id,ok"; else [ -n "$why" ] || why="failed"; answer "ack=$id,fail,$why"; fi
done
exit $rc
OWL_EOF
chmod +x /usr/bin/owlery-report.sh
touch /etc/crontabs/root
grep -v owlery-report /etc/crontabs/root > /tmp/owlery-cron
echo '* * * * * /usr/bin/owlery-report.sh' >> /tmp/owlery-cron
cp /tmp/owlery-cron /etc/crontabs/root && rm -f /tmp/owlery-cron
/etc/init.d/cron enable; /etc/init.d/cron restart
/usr/bin/owlery-report.sh && echo "owlery: sent" || echo "owlery: FAILED"
`

// deviceKinds are the kinds of network device that can be added.
var deviceKinds = map[string]bool{"mikrotik": true, "openwrt": true, store.KindKeenetic: true}

func (s *Server) newKeenetic(base, login, password string) (*keenetic.Client, error) {
	if s.KeeneticClient != nil {
		return s.KeeneticClient(base, login, password)
	}
	return keenetic.New(base, login, password)
}

// routerCredentials checks the login and password typed for a router that is asked.
func (s *Server) routerCredentials(w http.ResponseWriter, r *http.Request, login, password string) bool {
	if l := strings.TrimSpace(login); l == "" || len(l) > 64 || password == "" || len(password) > 128 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_credentials", "a login (up to 64 characters) and a password (up to 128) are required")
		return false
	}
	return true
}

// tryRouter signs in to the router with what was typed and reads it once. When that fails the answer says why.
func (s *Server) tryRouter(w http.ResponseWriter, r *http.Request, base, login, password string) (netdev.Report, bool) {
	c, err := s.newKeenetic(base, login, password)
	if err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_url", "the address must be https://name or https://name:port")
		return netdev.Report{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	rep, err := c.Poll(ctx)
	if err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "router_"+keenetic.Code(err), "the router could not be read: "+keenetic.Code(err))
		return netdev.Report{}, false
	}
	return rep, true
}

// createKeenetic adds a router that Owlery asks. The password is checked against the router first and then kept sealed.
func (s *Server) createKeenetic(w http.ResponseWriter, r *http.Request, a auth.Actor, name, rawURL, login, password string) {
	if s.Ring == nil {
		s.writeErr(w, r, http.StatusServiceUnavailable, "no_keys", "no master key is configured")
		return
	}
	base, err := keenetic.ParseBase(rawURL)
	if err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_url", "the address must be https://name or https://name:port")
		return
	}
	login = strings.TrimSpace(login)
	if !s.routerCredentials(w, r, login, password) {
		return
	}
	rep, ok := s.tryRouter(w, r, base, login, password)
	if !ok {
		return
	}
	id := store.NewNetDeviceID()
	sealed, err := s.Ring.Seal(store.NetPullAAD(id), []byte(password))
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	d, err := s.Store.CreatePullDevice(r.Context(), id, name, store.KindKeenetic, base, login, sealed, rep, time.Now().UTC())
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "name_taken", "a device with this name already exists")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "netdevice.create", "netdevice", d.ID, map[string]any{"name": d.Name, "kind": d.Kind, "url": base})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"device": d})
}

// changeRouterPassword gives a router that is asked a new password, after checking that the router accepts it.
func (s *Server) changeRouterPassword(w http.ResponseWriter, r *http.Request, a auth.Actor, id, password string) bool {
	if s.Ring == nil {
		s.writeErr(w, r, http.StatusServiceUnavailable, "no_keys", "no master key is configured")
		return false
	}
	devs, err := s.Store.PullDevices(r.Context())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return false
	}
	var dev *store.PullDevice
	for i := range devs {
		if devs[i].ID == id {
			dev = &devs[i]
		}
	}
	if dev == nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such router that is asked for its state")
		return false
	}
	if !s.routerCredentials(w, r, dev.Login, password) {
		return false
	}
	rep, ok := s.tryRouter(w, r, dev.URL, dev.Login, password)
	if !ok {
		return false
	}
	sealed, err := s.Ring.Seal(store.NetPullAAD(id), []byte(password))
	if err == nil {
		err = s.Store.SetPullSecret(r.Context(), id, sealed)
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return false
	}
	_ = s.Store.SaveNetReport(r.Context(), id, rep, time.Now().UTC())
	s.audit(r, a, "", "netdevice.password", "netdevice", id, nil)
	return true
}

// buildDeviceScript is what the page shows the owner once, with the token worked in.
func buildDeviceScript(kind, host, token string) string {
	if kind == "openwrt" {
		return strings.NewReplacer("@HOST@", host, "@PATH@", NetIngestPath, "@CPATH@", NetCommandsPath, "@TOKEN@", token).Replace(openwrtInstall)
	}
	return buildRouterScript(host, token)
}

// netIngest takes one piece of a device's report. The token is "<device id>.<secret>"; whatever is wrong with it, the answer is the same.
func (s *Server) netIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, ok := s.netAuth(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, netdev.MaxBody+1))
	if err != nil || len(body) > netdev.MaxBody {
		http.Error(w, "bad body", http.StatusRequestEntityTooLarge)
		return
	}
	rep, err := netdev.Parse(string(body))
	if err != nil {
		http.Error(w, "nothing usable", http.StatusUnprocessableEntity)
		return
	}
	if err := s.Store.SaveNetReport(r.Context(), id, rep, time.Now().UTC()); err != nil {
		http.Error(w, "not saved", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ownerOnly(w http.ResponseWriter, r *http.Request, a auth.Actor) bool {
	if !a.IsOwner {
		s.writeErr(w, r, http.StatusForbidden, "forbidden", "only the owner can do this")
		return false
	}
	return true
}

func (s *Server) listNetDevices(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	ds, err := s.Store.ListNetDevices(r.Context(), time.Now().UTC())
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"devices": ds})
}

// createNetDevice adds a device and returns its token and the script to paste into the router. The token is shown once.
func (s *Server) createNetDevice(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	var in struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		URL      string `json:"url"`
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 60 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "a name of up to 60 characters is required")
		return
	}
	if in.Kind == "" {
		in.Kind = "mikrotik"
	}
	if !deviceKinds[in.Kind] {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_kind", "unknown kind of device")
		return
	}
	if in.Kind == store.KindKeenetic {
		s.createKeenetic(w, r, a, in.Name, in.URL, in.Login, in.Password)
		return
	}
	secret, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	d, err := s.Store.CreateNetDevice(r.Context(), in.Name, in.Kind, store.HashAgentSecret(secret))
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "name_taken", "a device with this name already exists")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "netdevice.create", "netdevice", d.ID, map[string]any{"name": d.Name, "kind": d.Kind})
	token := d.ID + "." + secret
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"device": d, "token": token, "script": buildDeviceScript(d.Kind, r.Host, token)})
}

// updateNetDevice renames a device and/or says which router it stands behind; what is left out is not touched.
func (s *Server) renameNetDevice(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	var in struct {
		Name     *string `json:"name"`
		ParentID *string `json:"parent_id"`
		Password *string `json:"password"` // a new password, for a router that is asked
		Group    *string `json:"group"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	fail := func(err error) {
		switch {
		case errors.Is(err, store.ErrConflict):
			s.writeErr(w, r, http.StatusConflict, "name_taken", "cannot do that: the name is taken, or the parent would make a loop")
		case errors.Is(err, store.ErrNotFound):
			s.writeErr(w, r, http.StatusNotFound, "not_found", "no such device")
		default:
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		}
	}
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" || len(*in.Name) > 60 {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "a name of up to 60 characters is required")
			return
		}
		if err := s.Store.RenameNetDevice(r.Context(), id, *in.Name); err != nil {
			fail(err)
			return
		}
		s.audit(r, a, "", "netdevice.rename", "netdevice", id, map[string]any{"name": strings.TrimSpace(*in.Name)})
	}
	if in.Password != nil && !s.changeRouterPassword(w, r, a, id, *in.Password) {
		return
	}
	if in.Group != nil {
		if len(*in.Group) > 40 {
			s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "a group name of up to 40 characters")
			return
		}
		if err := s.Store.SetNetGroup(r.Context(), id, strings.TrimSpace(*in.Group)); err != nil {
			fail(err)
			return
		}
		s.audit(r, a, "", "netdevice.group", "netdevice", id, map[string]any{"group": strings.TrimSpace(*in.Group)})
	}
	if in.ParentID != nil {
		if err := s.Store.SetNetParent(r.Context(), id, *in.ParentID); err != nil {
			fail(err)
			return
		}
		s.audit(r, a, "", "netdevice.parent", "netdevice", id, map[string]any{"parent": *in.ParentID})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteNetDevice(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	if err := s.Store.DeleteNetDevice(r.Context(), r.PathValue("id")); err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such device")
		return
	}
	s.audit(r, a, "", "netdevice.delete", "netdevice", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

// confirmForwards marks the open ports of a router as looked at, which closes the alert about them.
func (s *Server) confirmForwards(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	err := s.Store.ConfirmForwards(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such router")
		return
	}
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "netdevice.forwards_confirm", "netdevice", r.PathValue("id"), nil)
	w.WriteHeader(http.StatusNoContent)
}
