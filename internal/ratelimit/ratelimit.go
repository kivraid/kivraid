// Package ratelimit provides per-key token-bucket rate limiting for the
// login endpoint. State is in-memory: after a restart limits reset, which
// is acceptable for brute-force protection.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	rate    rate.Limit
	burst   int
}

// New creates a limiter allowing r events per second with the given
// burst, tracked independently per key.
func New(r rate.Limit, burst int) *Limiter {
	return &Limiter{entries: map[string]*entry{}, rate: r, burst: burst}
}

func (l *Limiter) get(key string) *rate.Limiter {
	now := time.Now()
	e, ok := l.entries[key]
	if !ok {
		// Opportunistic cleanup: drop entries idle long enough to have
		// fully refilled, so the map cannot grow unbounded.
		if len(l.entries) > 10_000 {
			idle := time.Duration(float64(l.burst)/float64(l.rate)) * time.Second
			for k, v := range l.entries {
				if now.Sub(v.lastSeen) > idle {
					delete(l.entries, k)
				}
			}
		}
		e = &entry{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.entries[key] = e
	}
	e.lastSeen = now
	return e.limiter
}

// Allow consumes one token for key and reports whether the event may
// proceed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.get(key).Allow()
}

// Blocked reports whether key has no tokens left, without consuming one.
func (l *Limiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.get(key).Tokens() < 1
}
