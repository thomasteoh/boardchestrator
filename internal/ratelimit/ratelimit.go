// Package ratelimit is an in-memory, per-key token bucket (SPEC §7.11).
// Single-node only (PRD §19): state lives in this process.
package ratelimit

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Defaults bounding memory: at most MaxKeys buckets, idle ones swept at most
// every SweepEvery.
const (
	DefaultMaxKeys    = 100_000
	DefaultSweepEvery = time.Minute
)

// Limiter is a set of token buckets keyed by an arbitrary string (client IP,
// SCIM token id). Each key may make Burst requests at once and refills at
// PerMinute tokens a minute. Safe for concurrent use.
type Limiter struct {
	mu         sync.Mutex
	rate       float64 // tokens per second
	burst      float64
	maxKeys    int
	sweepEvery time.Duration
	lastSweep  time.Time
	buckets    map[string]bucket
	now        func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithClock sets the clock (tests).
func WithClock(now func() time.Time) Option { return func(l *Limiter) { l.now = now } }

// WithMaxKeys bounds the number of buckets held.
func WithMaxKeys(n int) Option { return func(l *Limiter) { l.maxKeys = n } }

// New returns a limiter allowing perMinute requests a minute per key with
// bursts of up to burst.
func New(perMinute, burst int, opts ...Option) *Limiter {
	l := &Limiter{
		rate:       float64(perMinute) / 60,
		burst:      float64(burst),
		maxKeys:    DefaultMaxKeys,
		sweepEvery: DefaultSweepEvery,
		buckets:    map[string]bucket{},
		now:        time.Now,
	}
	for _, o := range opts {
		o(l)
	}
	l.lastSweep = l.now()
	return l
}

// Allow takes a token for key. When none is left it reports false and how
// long until one will be.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= l.sweepEvery {
		l.sweep(now)
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.sweep(now)
			if len(l.buckets) >= l.maxKeys {
				l.evictOne()
			}
		}
		b = bucket{tokens: l.burst, last: now}
	} else if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+el*l.rate)
		b.last = now
	}
	if b.tokens < 1 {
		l.buckets[key] = b
		wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
		return false, wait
	}
	b.tokens--
	l.buckets[key] = b
	return true, 0
}

// Len is the number of buckets held (tests, metrics).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// sweep drops buckets that have refilled completely: forgetting them is
// indistinguishable from keeping them.
func (l *Limiter) sweep(now time.Time) {
	l.lastSweep = now
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// evictOne frees a slot when every bucket is still in use. Map iteration
// order is random, so a flood of keys cannot pick which ones go; an evicted
// key just starts again with a full bucket.
func (l *Limiter) evictOne() {
	for k := range l.buckets {
		delete(l.buckets, k)
		return
	}
}

// Middleware limits requests by key(r). Refused requests get 429 with
// Retry-After (whole seconds, at least 1); deny then writes the response,
// status 429 included. When deny is nil a plain-text 429 is written.
func (l *Limiter) Middleware(key func(*http.Request) string, deny http.HandlerFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok, wait := l.Allow(key(r))
			if ok {
				next.ServeHTTP(w, r)
				return
			}
			WriteRetryAfter(w, wait)
			w.Header().Set("Cache-Control", "no-store")
			if deny != nil {
				deny(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Too many requests. Please wait a moment and try again.\n"))
		})
	}
}

// WriteRetryAfter sets Retry-After to wait rounded up to whole seconds
// (minimum 1).
func WriteRetryAfter(w http.ResponseWriter, wait time.Duration) {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
}
