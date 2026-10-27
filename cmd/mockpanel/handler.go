package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// spec describes one pretend Remnawave panel. This is a development aid: it exists so
// the connection wizard and sync can be exercised end to end without a real panel.
type spec struct {
	Name        string
	Token       string
	Nodes       []map[string]any
	Users       []map[string]any
	DenyUsers   bool // answer 403 on /api/users/ to show a partial-capability panel
	NoBandwidth bool
}

func newHandler(s spec) http.Handler {
	mux := http.NewServeMux()
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"Unauthorized","statusCode":401}`))
				return
			}
			h(w, r)
		}
	}
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"response": v})
	}
	mux.HandleFunc("GET /api/nodes", authed(func(w http.ResponseWriter, r *http.Request) { reply(w, s.Nodes) }))
	mux.HandleFunc("GET /api/users/", authed(func(w http.ResponseWriter, r *http.Request) {
		if s.DenyUsers {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Forbidden","statusCode":403}`))
			return
		}
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		size, _ := strconv.Atoi(r.URL.Query().Get("size"))
		if size <= 0 || size > 500 {
			size = 100
		}
		if start < 0 || start > len(s.Users) {
			start = len(s.Users)
		}
		end := min(start+size, len(s.Users))
		reply(w, map[string]any{"users": s.Users[start:end], "total": len(s.Users)})
	}))
	mux.HandleFunc("GET /api/system/stats", authed(func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"uptime": 12345, "users": map[string]any{"totalUsers": len(s.Users)}})
	}))
	mux.HandleFunc("GET /api/bandwidth-stats/nodes", authed(func(w http.ResponseWriter, r *http.Request) {
		if s.NoBandwidth {
			http.NotFound(w, r)
			return
		}
		reply(w, map[string]any{"categories": []string{}, "sparklineData": []int{}, "topNodes": []any{}, "series": []any{}})
	}))
	mux.HandleFunc("GET /api/system/metadata", authed(func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"version": "3.4.5-mock"})
	}))
	return mux
}

func node(uuid, name, country string, connected bool, online int) map[string]any {
	return map[string]any{"uuid": uuid, "name": name, "countryCode": country, "isConnected": connected, "isDisabled": false,
		"usersOnline": online, "versions": map[string]any{"xray": "26.3.27", "node": "3.4.1"}}
}

// user mirrors Remnawave 3.4.x: a numeric id and no uuid.
func user(id int, name, status string) map[string]any {
	return map[string]any{"id": id, "shortUuid": fmt.Sprintf("sh%06d", id), "username": name, "status": status}
}

func uid(prefix string, n int) string { return fmt.Sprintf("%s-0000-4000-8000-%012d", prefix, n) }

// specs returns the two demo panels. They share some remote UUIDs and user names on
// purpose: Owlery must keep them apart.
func specs(homeToken, workToken string) (home, work spec) {
	home = spec{Name: "mock-home", Token: homeToken,
		Nodes: []map[string]any{
			node(uid("aaaaaaaa", 1), "home-a", "NL", true, 4),
			node(uid("aaaaaaaa", 2), "home-b", "DE", true, 1),
			node(uid("aaaaaaaa", 3), "home-c", "FI", false, 0),
		}}
	for i, n := range []string{"alice", "bob", "carol", "dave", "erin"} {
		home.Users = append(home.Users, user(i+1, n, "ACTIVE"))
	}
	work = spec{Name: "mock-work", Token: workToken, DenyUsers: true, NoBandwidth: true,
		Nodes: []map[string]any{
			node(uid("aaaaaaaa", 1), "work-1", "NL", true, 9), // same remote UUID as home-a
			node(uid("cccccccc", 2), "work-2", "SE", true, 3),
		}}
	for i, n := range []string{"alice", "frank", "grace"} { // "alice" exists in both panels
		work.Users = append(work.Users, user(i+1, n, "ACTIVE"))
	}
	return home, work
}
