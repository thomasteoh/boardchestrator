package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/auth"
)

// The exemption list is exactly SPEC §7.11's routes that exist so far. When
// WU-610/611/612 add theirs, they extend this expectation in the same change.
func TestCSRFExemptionListExact(t *testing.T) {
	want := []auth.CSRFExemption{
		{Method: http.MethodPost, Pattern: "/auth/oidc/{providerID}/backchannel-logout"},
	}
	if got := auth.CSRFExemptions(); !reflect.DeepEqual(got, want) {
		t.Fatalf("CSRF exemptions = %+v, want %+v", got, want)
	}
	// The returned slice is a copy.
	got := auth.CSRFExemptions()
	got[0].Pattern = "/"
	if auth.CSRFExemptions()[0].Pattern == "/" {
		t.Fatal("CSRFExemptions exposes the list")
	}
}

func TestIsCSRFExempt(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/auth/oidc/corp/backchannel-logout", true},
		{http.MethodPost, "/auth/oidc/acme-sso/backchannel-logout", true},
		{http.MethodGet, "/auth/oidc/corp/backchannel-logout", false},
		{http.MethodPut, "/auth/oidc/corp/backchannel-logout", false},
		{http.MethodPost, "/auth/oidc//backchannel-logout", false},
		{http.MethodPost, "/auth/oidc/corp/backchannel-logout/", false},
		{http.MethodPost, "/auth/oidc/corp/backchannel-logout/x", false},
		{http.MethodPost, "/auth/oidc/a/b/backchannel-logout", false},
		{http.MethodPost, "//auth/oidc/corp/backchannel-logout", false},
		{http.MethodPost, "/auth/logout", false},
		{http.MethodPost, "/auth/corp/callback", false},
		{http.MethodPost, "/api/action/task.create", false},
		{http.MethodPost, "/", false},
	} {
		if got := auth.IsCSRFExempt(tc.method, tc.path); got != tc.want {
			t.Errorf("IsCSRFExempt(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

// On an exempt route the session middleware does not resolve the cookie:
// the handler never sees a session (so cannot rely on one) and the CSRF
// middleware lets the POST through without a token.
func TestCSRFExemptRouteNeverSeesSession(t *testing.T) {
	var sawSession, sawCSRF bool
	h, store, _ := mwStack(t, func(w http.ResponseWriter, r *http.Request) {
		_, sawSession = auth.SessionFrom(r.Context())
		sawCSRF = auth.CSRFFrom(r.Context()) != ""
		w.WriteHeader(http.StatusOK)
	})
	raw, _, err := store.Create(context.Background(), "u1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/corp/backchannel-logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || sawSession || sawCSRF {
		t.Fatalf("exempt route: status %d, session %v, csrf %v", rec.Code, sawSession, sawCSRF)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("session cookie re-set on an exempt route")
	}
	// The same cookie on a non-exempt POST still needs the token.
	req = httptest.NewRequest(http.MethodPost, "/auth/oidc/corp/other", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: raw})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-exempt POST: %d", rec.Code)
	}
}

func TestReplayCache(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	c := auth.NewReplayCache(3).WithClock(func() time.Time { return now })
	exp := now.Add(time.Minute)
	if !c.Use("a", exp) || c.Use("a", exp) {
		t.Fatal("an id must be accepted once")
	}
	if !c.Use("b", exp) || !c.Use("c", exp) {
		t.Fatal("distinct ids refused")
	}
	// Full of live ids: fail closed rather than forget one.
	if c.Use("d", exp) || c.Use("a", exp) {
		t.Fatal("full cache accepted an id")
	}
	// Once they expire, the space is reclaimed and the old ids are usable
	// again (by then any token carrying them is no longer accepted).
	now = now.Add(2 * time.Minute)
	if !c.Use("d", now.Add(time.Minute)) || c.Len() != 1 || !c.Use("a", now.Add(time.Minute)) {
		t.Fatalf("expired ids not swept (len %d)", c.Len())
	}
	// Concurrent use stays consistent under -race.
	c = auth.NewReplayCache(0)
	done := make(chan bool)
	for i := 0; i < 8; i++ {
		go func() {
			ok := 0
			for j := 0; j < 50; j++ {
				if c.Use(fmt.Sprint("id-", j), time.Now().Add(time.Minute)) {
					ok++
				}
			}
			done <- ok > 0
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if c.Len() != 50 {
		t.Errorf("concurrent: %d ids", c.Len())
	}
}

func TestLogoutURLs(t *testing.T) {
	if got := auth.BackChannelLogoutURL("https://bc.example.com/", "corp"); got != "https://bc.example.com/auth/oidc/corp/backchannel-logout" {
		t.Error(got)
	}
	if got := auth.PostLogoutRedirectURL("https://bc.example.com"); got != "https://bc.example.com/login?signed_out=1" {
		t.Error(got)
	}
	if !auth.IsCSRFExempt(http.MethodPost, "/auth/oidc/corp/backchannel-logout") {
		t.Error("BackChannelLogoutURL path is not exempt")
	}
}
