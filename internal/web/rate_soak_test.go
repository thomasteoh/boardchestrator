package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// TestRateLimitSoak covers WU-407 AC: rate-limit soak under load. A single
// token bucket must admit exactly `capacity` requests, then reject every
// excess request until the refill window elapses, and recover (admit again)
// once a token has refilled — per key.
func TestRateLimitSoak(t *testing.T) {
	// Deterministic clock so the soak doesn't depend on real sleep.
	now := time.Now()
	b := newTokenBucket(5, 10*time.Millisecond)
	b.now = func() time.Time { return now }

	// Key A: fire 50 requests at burst 5 — exactly 5 admitted, 45 limited.
	admitted, limited := 0, 0
	for i := 0; i < 50; i++ {
		ok, _, _ := b.allow("keyA")
		if ok {
			admitted++
		} else {
			limited++
		}
	}
	if admitted != 5 || limited != 45 {
		t.Fatalf("keyA: admitted=%d limited=%d, want 5/45", admitted, limited)
	}

	// Key B (independent bucket): full burst available despite keyA exhaustion.
	if ok, _, _ := b.allow("keyB"); !ok {
		t.Fatalf("keyB first request denied — buckets must be per-key")
	}

	// After refill elapses, keyA recovers one token.
	now = now.Add(10 * time.Millisecond)
	ok, rem, _ := b.allow("keyA")
	if !ok {
		t.Fatalf("keyA did not recover after refill window")
	}
	if rem != 0 {
		t.Fatalf("keyA recovered to rem=%v, want 0 (single refill token)", rem)
	}
	// No second token until another window.
	if ok, _, _ := b.allow("keyA"); ok {
		t.Fatalf("keyA admitted a second token without another refill window")
	}
}

// TestRateLimitSoakAPI covers the API surface under load: the real v1 RPC
// handler (auth + dispatch) admits exactly the configured burst, then returns
// 429 rate_limited for every excess request. Uses a fresh limiter so the soak
// is deterministic and independent of the global one.
func TestRateLimitSoakAPI(t *testing.T) {
	db := dbtest.New(t)
	// Seed an API key for auth middleware to resolve (32-byte secret, per the
	// middleware's format check).
	secret := [32]byte{9, 9, 9, 9}
	sum := sha256.Sum256(secret[:])
	prefix := "bctsoak1"
	SetDispatcher(action.New(db))
	q := sqlc.New(db)
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ('u1','a@b.c','A')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO orgs (id, name, slug, visibility, context) VALUES ('org1','Acme','acme','private','')`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := q.CreateAPIKey(context.Background(), sqlc.CreateAPIKeyParams{
		ID: "key1", UserID: "u1", OrgID: "org1", Name: "soak",
		Prefix: prefix, Hash: hex.EncodeToString(sum[:]), ScopeJson: `{}`,
	}); err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	token := prefix + hex.EncodeToString(secret[:])

	// Fresh limiter: burst 3 with a large refill so the burst loop cannot
	// regenerate tokens mid-flight (deterministic 3/7). Recovery after refill
	// is covered deterministically by TestRateLimitSoak with a fake clock.
	b := newTokenBucket(3, time.Hour)
	b.now = func() time.Time { return time.Now() }
	h := auth.APIKeyAuthMiddleware(db)(handleRPCv1(b))

	ok, limited := 0, 0
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/actions/test.ping", strings.NewReader(`{"name":"x"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			limited++
			assertProblem(t, rec, "rate_limited")
		default:
			t.Fatalf("call %d: unexpected status %d", i, rec.Code)
		}
	}
	if ok != 3 || limited != 7 {
		t.Fatalf("API soak: ok=%d limited=%d, want 3/7", ok, limited)
	}
}
