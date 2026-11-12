package httpapi

import (
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
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
`

func buildRouterScript(host, token string) string {
	return strings.NewReplacer("@HOST@", host, "@PATH@", NetIngestPath, "@TOKEN@", token).Replace(routerScript)
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
var deviceKinds = map[string]bool{"mikrotik": true, "openwrt": true}

// buildDeviceScript is what the page shows the owner once, with the token worked in.
func buildDeviceScript(kind, host, token string) string {
	if kind == "openwrt" {
		return strings.NewReplacer("@HOST@", host, "@PATH@", NetIngestPath, "@TOKEN@", token).Replace(openwrtInstall)
	}
	return buildRouterScript(host, token)
}

// netIngest takes one piece of a device's report. The token is "<device id>.<secret>"; whatever is wrong with it, the answer is the same.
func (s *Server) netIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, secret, found := strings.Cut(h, ".")
	deny := func() { http.Error(w, "unauthorized", http.StatusUnauthorized) }
	if !ok || !found || id == "" || len(secret) < 20 || len(secret) > 200 {
		deny()
		return
	}
	want, _, err := s.Store.NetDeviceForAuth(r.Context(), id)
	got := store.HashAgentSecret(secret)
	if err != nil || subtle.ConstantTimeCompare(got, want) != 1 {
		deny()
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
		Name string `json:"name"`
		Kind string `json:"kind"`
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
