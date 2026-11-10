package store

import (
	"testing"
	"time"
)

func TestAFullCacheLosesItsOldestAnswersNotAllOfThem(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	m := map[string]memoEntry{}
	for i, k := range []string{"week", "a", "b", "c", "d"} {
		m[k] = memoEntry{v: k, at: t0.Add(time.Duration(i) * time.Minute)}
	}
	m["week"] = memoEntry{v: "week", at: t0.Add(10 * time.Minute)} // asked for again just now
	dropOldest(m, 2, func(e memoEntry) time.Time { return e.at })
	if len(m) != 2 || m["week"].v != "week" || m["d"].v != "d" {
		t.Fatalf("kept: %v", m)
	}
	dropOldest(m, 5, func(e memoEntry) time.Time { return e.at }) // nothing to do
	if len(m) != 2 {
		t.Fatalf("a cache that is not full was touched: %v", m)
	}
}
