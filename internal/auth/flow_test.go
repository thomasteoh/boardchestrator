package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/auth"
)

func TestFlowSealRoundTripAndExpiry(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	s, err := auth.NewFlowSealer("some-secret-key")
	if err != nil {
		t.Fatal(err)
	}
	s.WithClock(func() time.Time { return now })
	f, err := s.NewFlow("google", auth.IntentLogin)
	if err != nil {
		t.Fatal(err)
	}
	if f.State == "" || f.Nonce == "" || len(f.PKCEVerifier) < 43 {
		t.Fatalf("flow not randomised: %+v", f)
	}
	v, err := s.Seal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(v, f.State) || strings.Contains(v, f.PKCEVerifier) {
		t.Fatal("sealed flow exposes plaintext")
	}
	got, err := s.Open(v)
	if err != nil || got.State != f.State || got.PKCEVerifier != f.PKCEVerifier || got.ProviderID != "google" {
		t.Fatalf("Open = %+v, %v", got, err)
	}

	// A different BC_SECRET_KEY cannot open it.
	other, _ := auth.NewFlowSealer("another-secret-key")
	if _, err := other.Open(v); err == nil {
		t.Error("flow opened under another key")
	}
	// After 10 minutes it is expired.
	s.WithClock(func() time.Time { return now.Add(auth.FlowTTL) })
	if _, err := s.Open(v); err != auth.ErrFlowExpired {
		t.Errorf("expired flow: err = %v", err)
	}
	if err := f.Matches("github", f.State); err == nil {
		t.Error("flow matched the wrong provider")
	}
	if err := f.Matches("google", ""); err == nil {
		t.Error("flow matched an empty state")
	}
}
