package store

import (
	"fmt"
	"sync"
	"time"
)

// memo keeps the answers of the heavy analytics queries for catCacheTTL. Preset ranges end on a rounded time, so the
// same view asked again (another page, the same filter, a refresh) is the same key and costs nothing. Rule changes
// drop everything (dropAnalyticsCache), because the answers depend on them.
var memo = struct {
	sync.Mutex
	m map[string]memoEntry
}{m: map[string]memoEntry{}}

type memoEntry struct {
	v  any
	at time.Time
}

func memoized[T any](name string, q AnalyticsQuery, extra any, compute func() (T, error)) (T, error) {
	key := fmt.Sprintf("%s|%+v|%v", name, q, extra)
	memo.Lock()
	if e, ok := memo.m[key]; ok && time.Since(e.at) < catCacheTTL {
		memo.Unlock()
		return e.v.(T), nil
	}
	memo.Unlock()
	v, err := compute()
	if err != nil {
		var zero T
		return zero, err
	}
	memo.Lock()
	if len(memo.m) > 200 {
		memo.m = map[string]memoEntry{}
	}
	memo.m[key] = memoEntry{v: v, at: time.Now()}
	memo.Unlock()
	return v, nil
}

// SetAnalyticsCacheTTL changes how long analytics answers are kept and returns the previous value; tests turn it off
// (0) because they change data between two identical questions.
func SetAnalyticsCacheTTL(d time.Duration) time.Duration {
	old := catCacheTTL
	catCacheTTL = d
	return old
}
