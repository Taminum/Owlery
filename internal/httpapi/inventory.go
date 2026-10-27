package httpapi

import (
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Taminum/RemnaScope/internal/store"
)

// inventoryIn is the inventory of a server as the page sends it. Every field is replaced: what is left out is cleared.
type inventoryIn struct {
	Roles       []string `json:"roles"`
	OS          string   `json:"os"`
	Provider    string   `json:"provider"`
	Country     string   `json:"country"`
	City        string   `json:"city"`
	Group       string   `json:"group"`
	Tags        []string `json:"tags"`
	PurchasedOn string   `json:"purchased_on"` // YYYY-MM-DD or empty
}

// parse checks and tidies the inventory; the second value names the first field that is wrong.
func (in inventoryIn) parse() (store.Inventory, string) {
	var out store.Inventory
	for _, r := range in.Roles {
		if !slices.Contains(store.ServerRoles, r) {
			return out, "unknown role " + r
		}
		if !slices.Contains(out.Roles, r) {
			out.Roles = append(out.Roles, r)
		}
	}
	text := []struct {
		dst  *string
		src  string
		max  int
		name string
	}{{&out.OS, in.OS, 80, "os"}, {&out.Provider, in.Provider, 80, "provider"}, {&out.Country, in.Country, 60, "country"},
		{&out.City, in.City, 60, "city"}, {&out.Group, in.Group, 60, "group"}}
	for _, f := range text {
		v, ok := plainText(f.src, f.max)
		if !ok {
			return out, f.name + " must be at most " + strconv.Itoa(f.max) + " characters without control characters"
		}
		*f.dst = v
	}
	if len(in.Tags) > 20 {
		return out, "at most 20 tags"
	}
	for _, t := range in.Tags {
		v, ok := plainText(t, 30)
		if !ok || v == "" {
			return out, "a tag must be 1 to 30 characters without control characters"
		}
		if !slices.Contains(out.Tags, v) {
			out.Tags = append(out.Tags, v)
		}
	}
	if d := strings.TrimSpace(in.PurchasedOn); d != "" {
		t, err := time.Parse("2006-01-02", d)
		if err != nil {
			return out, "purchased_on must be YYYY-MM-DD"
		}
		out.PurchasedOn = &t
	}
	return out, ""
}

func plainText(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}
