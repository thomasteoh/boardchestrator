package auth

import (
	"sync"
	"time"
)

// ReplayCache remembers token ids (a logout token's jti; WU-610 SAML
// assertion ids) until they expire, so each is accepted at most once. It is
// in-memory (single node, PRD §19), mutex-guarded and bounded: when full of
// unexpired entries it refuses new ids rather than forgetting old ones, which
// would reopen them to replay. Only verified tokens are recorded, so filling
// it needs tokens signed by an identity provider.
type ReplayCache struct {
	mu      sync.Mutex
	max     int
	now     func() time.Time
	entries map[string]time.Time // id -> expiry
}

// DefaultReplayCacheSize bounds a ReplayCache built with size <= 0.
const DefaultReplayCacheSize = 10000

// NewReplayCache returns an empty cache holding at most size ids.
func NewReplayCache(size int) *ReplayCache {
	if size <= 0 {
		size = DefaultReplayCacheSize
	}
	return &ReplayCache{max: size, now: time.Now, entries: map[string]time.Time{}}
}

// WithClock overrides the cache's clock; test-only.
func (c *ReplayCache) WithClock(now func() time.Time) *ReplayCache {
	c.now = now
	return c
}

// Use records id until expires and reports true, or reports false when id is
// already recorded and unexpired (a replay) or the cache is full.
func (c *ReplayCache) Use(id string, expires time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if exp, ok := c.entries[id]; ok && now.Before(exp) {
		return false
	}
	if len(c.entries) >= c.max {
		for k, exp := range c.entries {
			if !now.Before(exp) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.max {
			return false
		}
	}
	c.entries[id] = expires
	return true
}

// Len is the number of ids held (including expired ones not yet swept).
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
