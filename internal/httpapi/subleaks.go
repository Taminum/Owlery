package httpapi

import (
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/alerts"
	"github.com/Taminum/Owlery/internal/asn"
	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/geoip"
	"github.com/Taminum/Owlery/internal/store"
)

type subLeakOut struct {
	PanelID   string    `json:"panel_id"`
	PanelName string    `json:"panel_name"`
	User      string    `json:"user"` // the panel's user id: with panel_id it names the subscription
	Label     string    `json:"label"`
	Note      string    `json:"note,omitempty"`
	IPs       int       `json:"ips"`
	Requests  int       `json:"requests"`
	Last      time.Time `json:"last"`
	Clients   []string  `json:"clients"`
	Level     string    `json:"level"` // leak | check
}

// clientName is the application in a user agent: what stands before the first slash or space ("Hiddify/2.0 (Android)").
func clientName(ua string) string {
	ua = strings.TrimSpace(ua)
	if i := strings.IndexAny(ua, "/ "); i > 0 {
		ua = ua[:i]
	}
	if len(ua) > 40 {
		ua = ua[:40]
	}
	return ua
}

func clientNames(agents []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, a := range agents {
		n := clientName(a)
		if n == "" || seen[strings.ToLower(n)] {
			continue
		}
		seen[strings.ToLower(n)] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func subWindow(w http.ResponseWriter, r *http.Request, s *Server) (days int, from, to time.Time, ok bool) {
	days = 7
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 30 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_range", "days must be 1 to 30")
			return
		}
		days = n
	}
	to = s.Now().UTC().Truncate(time.Minute).Add(time.Minute)
	return days, to.Add(-time.Duration(days) * 24 * time.Hour), to, true
}

// subscriptionLeaks lists the subscriptions that were asked for from several different addresses lately. It only
// reads what the panels reported; nothing is changed in a panel.
func (s *Server) subscriptionLeaks(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	days, from, to, ok := subWindow(w, r, s)
	if !ok {
		return
	}
	min := 5
	if v := r.URL.Query().Get("min"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 2 || n > 50 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_threshold", "min must be 2 to 50")
			return
		}
		min = n
	}
	scope := a.Scope()
	list, err := s.Store.SubLeaks(r.Context(), scope, from, to, min, 200)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	asked, err := s.Store.SubscriptionsAsked(r.Context(), scope, from, to)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	panels, err := s.Store.ListPanels(r.Context(), scope)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	names := map[string]string{}
	for _, p := range panels {
		names[p.ID] = p.Name
	}
	rows, fresh, flagged := []subLeakOut{}, 0, 0
	for _, l := range list {
		o := subLeakOut{PanelID: l.PanelID, PanelName: names[l.PanelID], User: l.RemoteUser, IPs: l.IPs, Requests: l.Requests, Last: l.Last.UTC(),
			Clients: clientNames(l.Agents), Level: "check"}
		o.Label, o.Note = s.label(a, l.PanelID, l.Name, l.RemoteUser, false)
		if l.IPs >= 2*min {
			o.Level = "leak"
		}
		if o.Level == "leak" {
			flagged++
		}
		if l.IPs >= min && l.IPsBefore < min {
			fresh++
		}
		rows = append(rows, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "days": days, "min": min, "asked": asked, "leaks": flagged,
		"new": fresh, "alert_ips": alerts.SubLeakIPs, "rows": rows})
}

type subLeakIPOut struct {
	IP       string    `json:"ip"`
	Country  string    `json:"country,omitempty"`
	Org      string    `json:"org,omitempty"`
	Hosting  bool      `json:"hosting"`
	Requests int       `json:"requests"`
	Last     time.Time `json:"last"`
	Client   string    `json:"client,omitempty"`
}

var hostingWords = []string{"hosting", "cloud", "server", "vps", "datacenter", "data center", "ovh", "hetzner", "digitalocean", "digital ocean",
	"amazon", "aws", "google", "microsoft", "azure", "contabo", "linode", "vultr", "choopa", "m247", "leaseweb", "selectel", "timeweb", "reg.ru"}

func looksLikeHosting(org string) bool {
	o := strings.ToLower(org)
	for _, w := range hostingWords {
		if strings.Contains(o, w) {
			return true
		}
	}
	return false
}

// subscriptionLeakIPs says from which addresses one subscription was asked for, with the country and network of each.
func (s *Server) subscriptionLeakIPs(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	_, from, to, ok := subWindow(w, r, s)
	if !ok {
		return
	}
	q := r.URL.Query()
	panelID, user := q.Get("panel_id"), strings.TrimSpace(q.Get("user"))
	if panelID == "" || user == "" || len(user) > 40 {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_subscription", "panel_id and user are required")
		return
	}
	if !a.Scope().Allows(panelID) {
		s.writeErr(w, r, http.StatusForbidden, "panel_forbidden", "panel is not available")
		return
	}
	list, err := s.Store.SubLeakIPs(r.Context(), panelID, user, from, to)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	geo, nets := geoip.Default(), asn.Default()
	out := make([]subLeakIPOut, 0, len(list))
	for _, x := range list {
		o := subLeakIPOut{IP: x.IP, Requests: x.Requests, Last: x.Last.UTC(), Client: clientName(x.Agent)}
		if ip, err := netip.ParseAddr(x.IP); err == nil {
			if code := geo.Country(ip); code != "" {
				o.Country = geoip.Name(code)
			}
			if ow, found := nets.Lookup(ip); found {
				o.Org, o.Hosting = ow.Org, looksLikeHosting(ow.Org)
			}
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ips": out})
}
