package server_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/server"
)

// TestLoginCookieSecureUnderProductionWiring drives a Google login through
// server.NewWithDB (the serve path) and asserts the session and flow cookies
// carry Secure — the WU-526 defect was an Insecure flag in this wiring.
func TestLoginCookieSecureUnderProductionWiring(t *testing.T) {
	idp := oidctest.New(t)
	idp.SetUser(oidctest.User{Subject: "admin-sub", Email: "admin@example.com", EmailVerified: true})
	d := dbtest.New(t)

	var h http.Handler
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	defer app.Close()

	cfg := testConfig()
	cfg.SessionSecret = "0123456789abcdef0123456789abcdef"
	cfg.BaseURL = app.URL
	cfg.AdminEmails = []string{"admin@example.com"}
	cfg.GoogleClientID, cfg.GoogleClientSecret = idp.ClientID, idp.ClientSecret
	cfg.GoogleIssuer = idp.Issuer()
	s := server.NewWithDB(cfg, d)
	s.SetReady(true)
	h = s

	b := oidctest.NewBrowser(t)
	steps, err := b.Follow(app.URL+"/auth/google", 5, func(next *url.URL) bool { return next.Path == "/app" })
	if err != nil {
		t.Fatal(err)
	}
	if got := steps[len(steps)-1].URL; got != app.URL+"/app" {
		t.Fatalf("login did not land on /app: %+v", steps)
	}

	var session, flow *http.Cookie
	for _, c := range b.SetCookies {
		switch {
		case c.Name == auth.CookieName && c.Value != "":
			session = c
		case c.Name == auth.FlowCookieName && c.Value != "":
			flow = c
		}
	}
	if session == nil || flow == nil {
		t.Fatalf("cookies not set: %+v", b.SetCookies)
	}
	for _, c := range []*http.Cookie{session, flow} {
		if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode {
			t.Errorf("%s attributes: %+v", c.Name, c)
		}
	}

	// Logout through the same wiring: CSRF-protected, revokes, clears.
	sum := sha256.Sum256([]byte(session.Value))
	hash := hex.EncodeToString(sum[:])
	req, _ := http.NewRequest(http.MethodPost, app.URL+"/auth/logout", nil)
	req.Header.Set(auth.CSRFHeader, auth.CSRFToken(cfg.SessionSecret, hash))
	resp, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status %d", resp.StatusCode)
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token_hash = ?`, hash).Scan(&n); err != nil || n != 0 {
		t.Errorf("session not revoked: n=%d err=%v", n, err)
	}
}

// TestLoginFailureRendersGenericPage: a failed callback renders the templ
// error page with a reference code and nothing from the underlying error.
func TestLoginFailureRendersGenericPage(t *testing.T) {
	idp := oidctest.New(t)
	idp.SetMisbehaviour(oidctest.Misbehaviour{WrongAudience: true})
	d := dbtest.New(t)
	var h http.Handler
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	defer app.Close()
	cfg := testConfig()
	cfg.BaseURL = app.URL
	cfg.GoogleClientID, cfg.GoogleClientSecret = idp.ClientID, idp.ClientSecret
	cfg.GoogleIssuer = idp.Issuer()
	if _, err := d.Exec(`UPDATE platform_settings SET bootstrap_done = 1`); err != nil {
		t.Fatal(err)
	}
	s := server.NewWithDB(cfg, d)
	h = s

	steps, err := oidctest.NewBrowser(t).Follow(app.URL+"/auth/google", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	end := steps[len(steps)-1]
	if end.Status != http.StatusForbidden {
		t.Fatalf("status %d", end.Status)
	}
	if !strings.Contains(end.Body, "Sign-in failed") || !strings.Contains(end.Body, "Reference:") {
		t.Errorf("not the generic page: %q", end.Body)
	}
	for _, leak := range []string{"aud", "oidc", "id_token", "someone-else", idp.ClientID} {
		if strings.Contains(end.Body, leak) {
			t.Errorf("page leaks %q", leak)
		}
	}
}
