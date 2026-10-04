package ratelimit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestBurstThenRefill(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	l := New(20, 10, WithClock(c.now))
	for i := range 10 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	ok, wait := l.Allow("a")
	if ok {
		t.Fatal("11th request allowed")
	}
	if wait <= 0 || wait > 3*time.Second {
		t.Fatalf("wait = %v, want ~3s (20/min)", wait)
	}
	// Another key is unaffected.
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("per-key buckets share tokens")
	}
	c.add(3 * time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("no token after 3s at 20/min")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("refilled more than one token in 3s")
	}
}

func TestSweepAndBound(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	l := New(60, 2, WithClock(c.now), WithMaxKeys(5))
	for i := range 5 {
		l.Allow(fmt.Sprint("k", i))
	}
	if l.Len() != 5 {
		t.Fatalf("len %d", l.Len())
	}
	// A sixth key at the bound evicts one; the map never grows past it.
	for i := 5; i < 50; i++ {
		l.Allow(fmt.Sprint("k", i))
		if l.Len() > 5 {
			t.Fatalf("len %d > bound", l.Len())
		}
	}
	// Idle buckets (refilled) are swept.
	c.add(2 * time.Minute)
	l.Allow("fresh")
	if l.Len() != 1 {
		t.Fatalf("after sweep len = %d, want 1", l.Len())
	}
}

func TestMiddleware(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	l := New(20, 1, WithClock(c.now))
	h := l.Middleware(func(r *http.Request) string { return r.Header.Get("K") }, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	do := func(k string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("K", k)
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := do("x"); rec.Code != 204 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec := do("x")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "3" {
		t.Fatalf("second: %d Retry-After=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestConcurrent(t *testing.T) {
	l := New(600, 100)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for range 50 {
				if ok, _ := l.Allow("same"); ok {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
				l.Allow(fmt.Sprint("own", i))
			}
		}(i)
	}
	wg.Wait()
	if allowed < 100 || allowed > 110 {
		t.Fatalf("allowed %d of 400 on one key with burst 100", allowed)
	}
}
