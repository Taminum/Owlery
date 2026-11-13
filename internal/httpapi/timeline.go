package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/auth"
	"github.com/Taminum/Owlery/internal/store"
)

type timelineOut struct {
	Site        string    `json:"site"`
	Service     string    `json:"service,omitempty"`
	Host        string    `json:"host"`
	Hosts       int       `json:"hosts"`
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	Connections int       `json:"connections"`
	Bytes       *int64    `json:"bytes"`
	Src         string    `json:"src"` // node | router | awg
	Node        string    `json:"node,omitempty"`
	Kind        string    `json:"kind"` // user | device | raw | awg
	Label       string    `json:"label"`
	Note        string    `json:"note,omitempty"`
	PanelName   string    `json:"panel_name"`
	Subject     string    `json:"subject,omitempty"`
}

// analyticsTimeline is the feed behind "search by domain": what was opened at the sites that match a part of a
// domain (or a service name), newest first. It knows domains only, never pages.
func (s *Server) analyticsTimeline(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	sc, ok := s.resolveScope(w, r, a)
	if !ok {
		return
	}
	qs := r.URL.Query()
	search := strings.TrimSpace(qs.Get("q"))
	if len(search) > 100 {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_search", "search is too long")
		return
	}
	var before time.Time
	if v := qs.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_before", "before must be a RFC 3339 time")
			return
		}
		before = t
	}
	limit := 200
	if v := qs.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			s.writeErr(w, r, http.StatusBadRequest, "invalid_paging", "limit must be 1 to 500")
			return
		}
		limit = n
	}
	meta, ok := s.mixedMeta(r, sc)
	if !ok {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	subj, ok := s.subjectFrom(w, r, sc)
	if !ok {
		return
	}
	src := qs.Get("src")
	if src != "" && src != "node" && src != "router" && src != "awg" {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_src", "src must be node, router or awg")
		return
	}
	out := struct {
		Meta   aMeta         `json:"meta"`
		Rows   []timelineOut `json:"rows"`
		More   bool          `json:"more"`
		Totals struct {
			Visits      int        `json:"visits"`
			Connections int        `json:"connections"`
			Sites       int        `json:"sites"`
			Last        *time.Time `json:"last"`
		} `json:"totals"`
	}{Meta: meta, Rows: []timelineOut{}}
	if meta.State == "ok" && search != "" {
		q := sc.query()
		q.Subject = subj
		rows, more, tot, err := s.Store.Timeline(r.Context(), q, search, qs.Get("raw") == "1", src, before, limit)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
			return
		}
		out.More = more
		out.Totals.Visits, out.Totals.Connections, out.Totals.Sites = tot.Visits, tot.Connections, tot.Sites
		if tot.Last != nil {
			l := tot.Last.UTC()
			out.Totals.Last = &l
		}
		for _, e := range rows {
			o := timelineOut{Site: e.Site, Service: e.Service, Host: e.Host, Hosts: e.Hosts, Start: e.Start.UTC(), End: e.End.UTC(), Connections: e.Connections,
				Src: e.Src, Node: e.NodeName, PanelName: sc.names[e.PanelID]}
			if e.Src == "router" && e.Bytes > 0 {
				b := e.Bytes
				o.Bytes = &b
			}
			switch {
			case e.AWG != "":
				o.Kind = "awg"
				o.Label = e.AWGName
				if o.Label == "" {
					o.Label = strings.TrimPrefix(e.AWG, "awg:")
				}
			case e.Device != "":
				o.Kind, o.Subject = "device", "device:"+e.PanelID+"|"+e.Device
				o.Label = e.Device
				if e.DeviceName != "" {
					o.Label = e.DeviceName + " (" + e.Device + ")"
				}
			case e.UserID != "":
				o.Kind, o.Subject = "user", "user:"+e.PanelID+"|"+e.UserID
				o.Label, o.Note = s.label(a, e.PanelID, e.DisplayName, e.Email, false)
			default:
				o.Kind, o.Subject = "raw", "raw:"+e.PanelID+"|"+e.Email
				o.Label, o.Note = s.label(a, e.PanelID, "", e.Email, false)
			}
			out.Rows = append(out.Rows, o)
		}
	}
	writeJSON(w, http.StatusOK, out)
}
