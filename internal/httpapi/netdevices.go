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
	}
	if !s.decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 60 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "a name of up to 60 characters is required")
		return
	}
	secret, err := auth.NewToken()
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	d, err := s.Store.CreateNetDevice(r.Context(), in.Name, store.HashAgentSecret(secret))
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "name_taken", "a device with this name already exists")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "netdevice.create", "netdevice", d.ID, map[string]any{"name": d.Name})
	token := d.ID + "." + secret
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"device": d, "token": token, "script": buildRouterScript(r.Host, token)})
}

func (s *Server) renameNetDevice(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.ownerOnly(w, r, a) {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 60 {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_name", "a name of up to 60 characters is required")
		return
	}
	err := s.Store.RenameNetDevice(r.Context(), r.PathValue("id"), in.Name)
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeErr(w, r, http.StatusConflict, "name_taken", "a device with this name already exists")
		return
	case errors.Is(err, store.ErrNotFound):
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such device")
		return
	case err != nil:
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	s.audit(r, a, "", "netdevice.rename", "netdevice", r.PathValue("id"), map[string]any{"name": strings.TrimSpace(in.Name)})
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
