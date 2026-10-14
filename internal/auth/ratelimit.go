package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a keyed token-bucket limiter with bounded memory.
type Limiter struct {
	mu      sync.Mutex
	rate    rate.Limit
	burst   int
	max     int
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	l    *rate.Limiter
	seen time.Time
}

// NewLimiter allows `burst` events immediately, refilling at perSecond.
func NewLimiter(perSecond float64, burst int) *Limiter {
	return &Limiter{rate: rate.Limit(perSecond), burst: burst, max: 10000, buckets: map[string]*bucket{}, now: time.Now}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.max {
			l.evict(now)
		}
		b = &bucket{l: rate.NewLimiter(l.rate, l.burst)}
		l.buckets[key] = b
	}
	b.seen = now
	return b.l.AllowN(now, 1)
}

// evict drops idle buckets; if everything is busy it drops the oldest half.
func (l *Limiter) evict(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.seen) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) < l.max {
		return
	}
	i := 0
	for k := range l.buckets {
		delete(l.buckets, k)
		if i++; i >= l.max/2 {
			break
		}
	}
}
