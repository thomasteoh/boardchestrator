package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

func newStore(t *testing.T) (*auth.SessionStore, context.Context) {
	t.Helper()
	d := dbtest.New(t)
	ctx := context.Background()
	// A session references a user; create one to satisfy the foreign key.
	if _, err := d.ExecContext(ctx, `INSERT INTO users (id, email) VALUES (?, ?)`, "u1", "u1@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return auth.NewSessionStore(d), ctx
}

func TestSessionCreateAndLookup(t *testing.T) {
	store, ctx := newStore(t)

	raw, sess, err := store.Create(ctx, "u1", "1.2.3.4", "test-ua")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if raw == "" {
		t.Fatal("Create returned empty token")
	}
	if len(raw) != 64 { // 32 bytes hex-encoded
		t.Errorf("token length = %d, want 64 hex chars", len(raw))
	}
	if sess.UserID != "u1" {
		t.Errorf("session user = %q, want u1", sess.UserID)
	}

	got, err := store.Lookup(ctx, raw)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.UserID != "u1" {
		t.Errorf("looked-up user = %q, want u1", got.UserID)
	}
	if got.IP != "1.2.3.4" {
		t.Errorf("ip = %q, want 1.2.3.4", got.IP)
	}
}

func TestSessionLookupUnknownToken(t *testing.T) {
	store, ctx := newStore(t)
	if _, err := store.Lookup(ctx, "deadbeef"); err != auth.ErrNoSession {
		t.Errorf("Lookup(unknown) err = %v, want ErrNoSession", err)
	}
	if _, err := store.Lookup(ctx, ""); err != auth.ErrNoSession {
		t.Errorf("Lookup(empty) err = %v, want ErrNoSession", err)
	}
}

func TestSessionExpiredRejected(t *testing.T) {
	store, ctx := newStore(t)

	// Create at t0; the sliding TTL sets expiry at t0+SlidingTTL.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.WithClock(func() time.Time { return base })
	raw, _, err := store.Create(ctx, "u1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Advance the clock past the sliding TTL: session must be rejected.
	store.WithClock(func() time.Time { return base.Add(auth.SlidingTTL + time.Minute) })
	if _, err := store.Lookup(ctx, raw); err != auth.ErrNoSession {
		t.Fatalf("Lookup(expired) err = %v, want ErrNoSession", err)
	}

	// And it must have been purged: a second lookup still rejects.
	if _, err := store.Lookup(ctx, raw); err != auth.ErrNoSession {
		t.Errorf("expired session not deleted: err = %v", err)
	}
}

func TestSessionSlidingExpiry(t *testing.T) {
	store, ctx := newStore(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.WithClock(func() time.Time { return base })
	raw, sess, err := store.Create(ctx, "u1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	firstExpiry := sess.ExpiresAt

	// Look up a day later; expiry should slide forward from the new "now".
	store.WithClock(func() time.Time { return base.Add(24 * time.Hour) })
	got, err := store.Lookup(ctx, raw)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got.ExpiresAt.After(firstExpiry) {
		t.Errorf("expiry did not slide: got %v, first %v", got.ExpiresAt, firstExpiry)
	}
}

func TestSessionAbsoluteCap(t *testing.T) {
	store, ctx := newStore(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := base
	store.WithClock(func() time.Time { return now })
	raw, _, err := store.Create(ctx, "u1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	absCap := base.Add(auth.AbsoluteTTL)

	// Keep the session alive with periodic lookups (each slides expiry). The
	// sliding expiry must never exceed the absolute cap even under continuous
	// activity right up to the cap.
	step := auth.SlidingTTL / 2
	for now.Before(absCap.Add(-step)) {
		now = now.Add(step)
		got, err := store.Lookup(ctx, raw)
		if err != nil {
			t.Fatalf("Lookup at %v: %v", now, err)
		}
		if got.ExpiresAt.After(absCap) {
			t.Fatalf("expiry %v exceeds absolute cap %v", got.ExpiresAt, absCap)
		}
	}
}

func TestSessionRotateInvalidatesOld(t *testing.T) {
	store, ctx := newStore(t)
	oldRaw, _, err := store.Create(ctx, "u1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	newRaw, newSess, err := store.Rotate(ctx, oldRaw, "5.6.7.8", "new-ua")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newRaw == oldRaw {
		t.Fatal("Rotate returned the same token")
	}
	if newSess.UserID != "u1" {
		t.Errorf("rotated session user = %q, want u1", newSess.UserID)
	}

	// Old token must no longer resolve.
	if _, err := store.Lookup(ctx, oldRaw); err != auth.ErrNoSession {
		t.Errorf("old token still valid after rotate: err = %v", err)
	}
	// New token resolves.
	if _, err := store.Lookup(ctx, newRaw); err != nil {
		t.Errorf("new token invalid after rotate: %v", err)
	}
}

func TestSessionRevoke(t *testing.T) {
	store, ctx := newStore(t)
	raw, _, err := store.Create(ctx, "u1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.Revoke(ctx, raw); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := store.Lookup(ctx, raw); err != auth.ErrNoSession {
		t.Errorf("revoked session still valid: err = %v", err)
	}
	// Revoking again / unknown is a no-op.
	if err := store.Revoke(ctx, raw); err != nil {
		t.Errorf("Revoke(already gone): %v", err)
	}
	if err := store.Revoke(ctx, ""); err != nil {
		t.Errorf("Revoke(empty): %v", err)
	}
}

func TestSessionPurgeExpired(t *testing.T) {
	store, ctx := newStore(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.WithClock(func() time.Time { return base })
	raw, _, err := store.Create(ctx, "u1", "", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	store.WithClock(func() time.Time { return base.Add(auth.SlidingTTL + time.Hour) })
	if err := store.PurgeExpired(ctx); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if _, err := store.Lookup(ctx, raw); err != auth.ErrNoSession {
		t.Errorf("purged session still present: err = %v", err)
	}
}
