package httpapi

import (
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/geoip"
	"github.com/Taminum/Owlery/internal/store"
)

type summaryIP struct {
	store.SummaryIP
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
}

type summaryOut struct {
	store.FleetSummary
	Hourly []store.SummaryHour   `json:"hourly"`
	TopIPs []summaryIP           `json:"top_ips"`
	Jails  []store.SummaryJail   `json:"jails"`
	Recent []store.SummaryEvent  `json:"recent"`
	From   time.Time             `json:"from"`
	To     time.Time             `json:"to"`
	Owlery *store.OwleryActivity `json:"owlery"` // only for an owner: sign-ins belong to no panel
}

// fleetSummary is the home page's one look at the last day: bans hour by hour, the top lists, changes,
// certificates, who did what in Owlery.
func (s *Server) fleetSummary(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	hours := 24
	if h, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && h >= 1 && h <= 168 {
		hours = h
	}
	to := s.Now().UTC()
	from := to.Add(-time.Duration(hours) * time.Hour)
	fail := func() { s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error") }
	sum, err := s.Store.FleetSummary(r.Context(), a.Scope(), from, to)
	if err != nil {
		fail()
		return
	}
	det, err := s.Store.FleetDetails(r.Context(), a.Scope(), from, to, a.IsOwner)
	if err != nil {
		fail()
		return
	}
	out := summaryOut{FleetSummary: sum, Hourly: det.Hourly, Jails: det.Jails, Recent: det.Recent, From: from, To: to, TopIPs: []summaryIP{}}
	db := geoip.Default()
	for _, x := range det.TopIPs {
		row := summaryIP{SummaryIP: x}
		if ip, err := netip.ParseAddr(x.IP); err == nil && db != nil {
			if code := db.Country(ip.Unmap()); code != "" {
				row.Country, row.CountryName = code, geoip.Name(code)
			}
		}
		out.TopIPs = append(out.TopIPs, row)
	}
	if a.IsOwner {
		act, err := s.Store.OwleryActivity(r.Context(), from, to)
		if err != nil {
			fail()
			return
		}
		out.Owlery = &act
	}
	writeJSON(w, http.StatusOK, out)
}
