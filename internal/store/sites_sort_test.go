package store

import "testing"

func TestSortSites(t *testing.T) {
	list := []SiteRow{{Site: "b.com", Connections: 5, Users: 1}, {Site: "a.com", Connections: 5, Users: 3}, {Site: "c.com", Connections: 9, Users: 2}}
	names := func() string {
		out := ""
		for _, r := range list {
			out += r.Site + " "
		}
		return out
	}
	sortSites(list, "", false)
	if got := names(); got != "c.com a.com b.com " {
		t.Fatalf("default is most connections first, ties by name: %q", got)
	}
	sortSites(list, "users", false)
	if got := names(); got != "b.com c.com a.com " {
		t.Fatalf("users ascending: %q", got)
	}
	sortSites(list, "site", true)
	if got := names(); got != "c.com b.com a.com " {
		t.Fatalf("site descending: %q", got)
	}
}
