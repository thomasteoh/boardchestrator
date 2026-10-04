package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/config"
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

// TestGenericOIDCProviderFromEnv: a provider configured purely through
// BC_OIDC_<NAME>_* variables is seeded at startup and logs in end to end
// (WU-602), with its groups claim mapped.
func TestGenericOIDCProviderFromEnv(t *testing.T) {
	idp := oidctest.New(t)
	idp.SetUser(oidctest.User{Subject: "corp-sub", Email: "admin@example.com", EmailVerified: true,
		Extra: map[string]any{"realm_access": map[string]any{"roles": []string{"staff"}}}})
	d := dbtest.New(t)
	var h http.Handler
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	defer app.Close()

	for k, v := range map[string]string{
		"BC_SECRET_KEY":                  "test-secret-key",
		"BC_SESSION_SECRET":              "0123456789abcdef0123456789abcdef",
		"BC_BASE_URL":                    app.URL,
		"BC_ADMIN_EMAILS":                "admin@example.com",
		"BC_OIDC_CORP_SSO_ISSUER":        idp.Issuer(),
		"BC_OIDC_CORP_SSO_CLIENT_ID":     idp.ClientID,
		"BC_OIDC_CORP_SSO_CLIENT_SECRET": idp.ClientSecret,
		"BC_OIDC_CORP_SSO_PRESET":        "keycloak",
		"BC_OIDC_CORP_SSO_DISPLAY_NAME":  "Corp SSO",
		"BC_OIDC_CORP_SSO_GROUPS_CLAIM":  "realm_access.roles",
		"BC_OIDC_CORP_SSO_SCOPES":        "openid email profile",
	} {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	s := server.NewWithDB(cfg, d)
	h = s

	steps, err := oidctest.NewBrowser(t).Follow(app.URL+"/auth/corp-sso", 5, func(next *url.URL) bool { return next.Path == "/app" })
	if err != nil {
		t.Fatal(err)
	}
	if got := steps[len(steps)-1].URL; got != app.URL+"/app" {
		t.Fatalf("login did not land on /app: %+v", steps)
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM identities WHERE provider = 'corp-sso' AND subject = 'corp-sub'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("identity: n=%d err=%v", n, err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM sessions WHERE provider_id = 'corp-sso' AND auth_method = 'oidc'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("session provenance: n=%d err=%v", n, err)
	}
	ps, err := s.IdP().Providers(context.Background())
	if err != nil || len(ps) != 1 || ps[0].ID != "corp-sso" || ps[0].DisplayName != "Corp SSO" || ps[0].ManagedBy != "env" {
		t.Errorf("providers %+v %v", ps, err)
	}
	if ar := idp.AuthorizeRequests(); len(ar) != 1 || ar[0].RedirectURI != app.URL+"/auth/corp-sso/callback" {
		t.Errorf("authorize %+v", ar)
	}
}

// TestNoSignInProviderWarns: without any provider the server still starts
// (Google is optional) and logs a warning.
func TestNoSignInProviderWarns(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	s := server.NewWithDB(testConfig(), dbtest.New(t))
	if !strings.Contains(buf.String(), "no sign-in provider is configured") {
		t.Errorf("no warning logged: %s", buf.String())
	}
	srv := httptest.NewServer(s)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/auth/google")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/auth/google without config: %d", resp.StatusCode)
	}
}
