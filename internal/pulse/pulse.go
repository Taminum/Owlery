// Package pulse keeps the latest quick reading of each machine in memory. It is for what a person watches move on the
// server card; it is never stored, and a reading that is not fresh is not used.
package pulse

import (
	"sync"
	"time"

	"github.com/Taminum/Owlery/internal/secproto"
)

type entry struct {
	p  secproto.Pulse
	at time.Time // when the server got it, not when the agent made it: the clocks may differ
}

type Cache struct {
	mu sync.RWMutex
	m  map[string]entry
}

func New() *Cache { return &Cache{m: map[string]entry{}} }

// Set remembers a machine's latest pulse.
func (c *Cache) Set(vpsID string, p secproto.Pulse, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[vpsID] = entry{p, now}
}

// Get returns the machine's pulse if it arrived no longer than maxAge ago.
func (c *Cache) Get(vpsID string, now time.Time, maxAge time.Duration) (secproto.Pulse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.m[vpsID]
	if !ok || now.Sub(e.at) > maxAge {
		return secproto.Pulse{}, false
	}
	return e.p, true
}

// Forget drops a machine's pulse, so that a revoked or removed one does not show a reading it can no longer make.
func (c *Cache) Forget(vpsID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, vpsID)
}
