package auth_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	authidp "github.com/thomasteoh/boardchestrator/internal/auth/idp"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/perm"
)

// countRealUsers excludes migration 0017's "Former member" sentinel.
const countRealUsers = `SELECT COUNT(*) FROM users WHERE id <> 'ffffffffffffffffffffffffffffffff'`

const testSessionSecret = "0123456789abcdef0123456789abcdef"

// loginHarness is the login stack (session + CSRF middleware, login routes)
// over a real temp DB, with Google pointed at an oidctest IdP.
type loginHarness struct {
	t   *testing.T
	db  *sql.DB
	idp *oidctest.Server
	app *httptest.Server
	h   *auth.Handler
}

type harnessOpts struct {
	notBootstrapped bool
	adminEmails     []string
	github          *authidp.GitHubConfig
	encKey          []byte
}

func newLoginHarness(t *testing.T, o harnessOpts) *loginHarness {
	t.Helper()
	d := dbtest.New(t)
	if !o.notBootstrapped {
		if _, err := d.Exec(`UPDATE platform_settings SET bootstrap_done = 1`); err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
	}
	idp := oidctest.New(t)
	var router http.Handler
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { router.ServeHTTP(w, r) }))
	t.Cleanup(app.Close)

	store := auth.NewSessionStore(d)
	conns := []auth.Connector{authidp.NewGoogleConnector(idp.Issuer(), idp.ClientID, idp.ClientSecret, app.URL, nil)}
	if o.github != nil {
		gc := *o.github
		gc.BaseURL = app.URL
		conns = append(conns, authidp.NewGitHubConnector(gc))
	}
	h, err := auth.NewHandler(auth.HandlerConfig{
		DB:          d,
		Sessions:    store,
		SecretKey:   "test-secret-key-for-flow-cookies",
		EncKey:      o.encKey,
		BaseURL:     app.URL,
		AdminEmails: o.adminEmails,
		Connectors:  conns,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	sc := auth.SessionConfig{Store: store, Secret: testSessionSecret}
	r := chi.NewRouter()
	r.Use(sc.Session())
	r.Use(sc.CSRF())
	h.Routes(r)
	r.Get("/app", func(w http.ResponseWriter, r *http.Request) {
		s, ok := auth.SessionFrom(r.Context())
		if !ok {
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "user="+s.UserID)
	})
	r.Get("/", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "home") })
	router = r
	return &loginHarness{t: t, db: d, idp: idp, app: app, h: h}
}

// login runs a full Google login for b and returns the hops.
func (lh *loginHarness) login(b *oidctest.Browser, hint string) []oidctest.Step {
	lh.t.Helper()
	u := lh.app.URL + "/auth/google"
	if hint != "" {
		u += "?login_hint=" + url.QueryEscape(hint)
	}
	steps, err := b.Follow(u, 5, nil)
	if err != nil {
		lh.t.Fatalf("login: %v", err)
	}
	return steps
}

// toCallback runs the flow up to (not including) the callback and returns
// the callback URL the IdP redirected to.
func (lh *loginHarness) toCallback(b *oidctest.Browser) string {
	lh.t.Helper()
	steps, err := b.Follow(lh.app.URL+"/auth/google", 5, func(next *url.URL) bool {
		return strings.HasSuffix(next.Path, "/callback")
	})
	if err != nil {
		lh.t.Fatalf("toCallback: %v", err)
	}
	return steps[len(steps)-1].URL
}

func (lh *loginHarness) get(b *oidctest.Browser, u string) (int, string) {
	lh.t.Helper()
	resp, err := b.Get(u)
	if err != nil {
		lh.t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (lh *loginHarness) count(q string, args ...any) int {
	lh.t.Helper()
	var n int
	if err := lh.db.QueryRow(q, args...).Scan(&n); err != nil {
		lh.t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func (lh *loginHarness) sessionCookie(b *oidctest.Browser) string {
	if c := b.Cookie(lh.app.URL, auth.CookieName); c != nil {
		return c.Value
	}
	return ""
}

func last(steps []oidctest.Step) oidctest.Step { return steps[len(steps)-1] }

func tokenHash(raw string) string {
	s := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(s[:])
}

// leakMarkers are fragments of internal/upstream error text that must never
// reach a client.
var leakMarkers = []string{"oidc", "id_token", "nonce", "verify", "token", "issuer", "audience",
	"expired", "github:", "client_secret", "status ", "127.0.0.1", "UPSTREAM", "sql", "auth:"}

func assertNoLeak(t *testing.T, body string, extra ...string) {
	t.Helper()
	low := strings.ToLower(body)
	for _, m := range append(leakMarkers, extra...) {
		if strings.Contains(low, strings.ToLower(m)) {
			t.Errorf("response body leaks %q: %q", m, body)
		}
	}
	if !strings.Contains(body, "Reference:") {
		t.Errorf("failure body has no reference code: %q", body)
	}
}

func TestLoginFirstThenSecond(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	lh.idp.SetUser(oidctest.User{Subject: "alice-sub", Email: "alice@example.com", EmailVerified: true, Name: "Alice"})

	b := oidctest.NewBrowser(t)
	steps := lh.login(b, "")
	end := last(steps)
	if end.Status != http.StatusOK || !strings.HasPrefix(end.Body, "user=") {
		t.Fatalf("first login ended %d %q (steps %+v)", end.Status, end.Body, steps)
	}
	firstUser := strings.TrimPrefix(end.Body, "user=")
	if n := lh.count(`SELECT COUNT(*) FROM users WHERE email = 'alice@example.com'`); n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
	if n := lh.count(`SELECT COUNT(*) FROM identities WHERE provider='google' AND subject='alice-sub' AND last_login_at IS NOT NULL`); n != 1 {
		t.Fatalf("identities = %d, want 1", n)
	}
	// PKCE S256 and nonce were sent; the token request carried a verifier.
	ar := lh.idp.AuthorizeRequests()[0]
	if ar.CodeChallengeMethod != "S256" || ar.CodeChallenge == "" || ar.Nonce == "" {
		t.Errorf("authorize request lacks PKCE/nonce: %+v", ar)
	}
	if tr := lh.idp.TokenRequests(); len(tr) != 1 || tr[0].CodeVerifier == "" {
		t.Errorf("token requests = %+v", tr)
	}
	// Session records provenance.
	var prov, method, subj, idTok string
	if err := lh.db.QueryRow(`SELECT provider_id, auth_method, idp_subject, id_token_enc FROM sessions WHERE token_hash = ?`,
		tokenHash(lh.sessionCookie(b))).Scan(&prov, &method, &subj, &idTok); err != nil {
		t.Fatalf("session row: %v", err)
	}
	if prov != "google" || method != auth.AuthMethodOIDC || subj != "alice-sub" {
		t.Errorf("session provenance = %q %q %q", prov, method, subj)
	}

	// Second login, fresh browser: same user, no error, no duplicate rows.
	b2 := oidctest.NewBrowser(t)
	end2 := last(lh.login(b2, ""))
	if end2.Status != http.StatusOK || end2.Body != "user="+firstUser {
		t.Fatalf("second login ended %d %q, want user=%s", end2.Status, end2.Body, firstUser)
	}
	if n := lh.count(countRealUsers); n != 1 {
		t.Errorf("users after second login = %d, want 1", n)
	}
	if n := lh.count(`SELECT COUNT(*) FROM identities`); n != 1 {
		t.Errorf("identities after second login = %d, want 1", n)
	}
}

func TestLoginFlowCookieAttributesAndCleared(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	b := oidctest.NewBrowser(t)
	lh.login(b, "")
	var set, cleared bool
	for _, c := range b.SetCookies {
		if c.Name != auth.FlowCookieName {
			continue
		}
		if !c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteLaxMode {
			t.Errorf("flow cookie attributes wrong: %+v", c)
		}
		if c.MaxAge == 600 {
			set = true
		}
		if c.MaxAge < 0 {
			cleared = true
		}
	}
	if !set || !cleared {
		t.Errorf("flow cookie set=%v cleared=%v", set, cleared)
	}
	if b.Cookie(lh.app.URL, auth.FlowCookieName) != nil {
		t.Error("flow cookie still held after callback")
	}
}

func TestLoginRejectsBadFlow(t *testing.T) {
	cases := map[string]func(lh *loginHarness, b *oidctest.Browser) string{
		"wrong state": func(lh *loginHarness, b *oidctest.Browser) string {
			cb, _ := url.Parse(lh.toCallback(b))
			q := cb.Query()
			q.Set("state", "forged-state")
			cb.RawQuery = q.Encode()
			return cb.String()
		},
		"missing state": func(lh *loginHarness, b *oidctest.Browser) string {
			cb, _ := url.Parse(lh.toCallback(b))
			q := cb.Query()
			q.Del("state")
			cb.RawQuery = q.Encode()
			return cb.String()
		},
		"missing flow cookie": func(lh *loginHarness, b *oidctest.Browser) string {
			cb := lh.toCallback(b)
			b.DeleteCookie(lh.app.URL, auth.FlowCookieName)
			return cb
		},
		"tampered flow cookie": func(lh *loginHarness, b *oidctest.Browser) string {
			cb := lh.toCallback(b)
			c := b.Cookie(lh.app.URL, auth.FlowCookieName)
			b.SetCookie(lh.app.URL, &http.Cookie{Name: c.Name, Value: c.Value[:len(c.Value)-2] + "AA"})
			return cb
		},
		"flow cookie from another flow": func(lh *loginHarness, b *oidctest.Browser) string {
			// The victim's browser holds its own flow cookie; the attacker's
			// callback URL (code+state from a different flow) is replayed.
			attacker := oidctest.NewBrowser(lh.t)
			cb := lh.toCallback(attacker)
			lh.toCallback(b)
			return cb
		},
		"flow for another provider": func(lh *loginHarness, b *oidctest.Browser) string {
			cb := lh.toCallback(b)
			return strings.Replace(cb, "/auth/google/callback", "/auth/github/callback", 1)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lh := newLoginHarness(t, harnessOpts{github: &authidp.GitHubConfig{ClientID: "x", ClientSecret: "y", WebBase: "http://127.0.0.1:1", APIBase: "http://127.0.0.1:1"}})
			b := oidctest.NewBrowser(t)
			cb := mk(lh, b)
			status, body := lh.get(b, cb)
			if status != http.StatusBadRequest {
				t.Errorf("status %d, want 400 (body %q)", status, body)
			}
			assertNoLeak(t, body)
			if lh.sessionCookie(b) != "" {
				t.Error("session cookie issued")
			}
			if n := lh.count(countRealUsers); n != 0 {
				t.Errorf("users = %d, want 0", n)
			}
			if b.Cookie(lh.app.URL, auth.FlowCookieName) != nil {
				t.Error("flow cookie not cleared on failure")
			}
		})
	}
}

func TestLoginRejectsBadIDToken(t *testing.T) {
	cases := map[string]oidctest.Misbehaviour{
		"wrong aud":   {WrongAudience: true},
		"wrong iss":   {WrongIssuer: true},
		"wrong nonce": {WrongNonce: true},
		"no nonce":    {OmitNonce: true},
		"expired":     {Expired: true},
		"alg none":    {AlgNone: true},
		"wrong key":   {WrongKey: true},
		"userinfo sub mismatch": {
			OmitEmailFromIDToken: true, UserinfoSubject: "someone-else",
		},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lh := newLoginHarness(t, harnessOpts{})
			lh.idp.SetMisbehaviour(m)
			b := oidctest.NewBrowser(t)
			end := last(lh.login(b, ""))
			if end.Status != http.StatusForbidden {
				t.Errorf("status %d, want 403 (body %q)", end.Status, end.Body)
			}
			assertNoLeak(t, end.Body)
			if lh.sessionCookie(b) != "" {
				t.Error("session cookie issued")
			}
			if n := lh.count(countRealUsers); n != 0 {
				t.Errorf("users = %d, want 0", n)
			}
		})
	}
}

func TestLoginUserinfoFillsMissingEmail(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	lh.idp.SetMisbehaviour(oidctest.Misbehaviour{OmitEmailFromIDToken: true})
	b := oidctest.NewBrowser(t)
	if end := last(lh.login(b, "")); end.Status != http.StatusOK {
		t.Fatalf("status %d %q", end.Status, end.Body)
	}
	if n := lh.count(`SELECT COUNT(*) FROM users WHERE email = 'user1@example.com'`); n != 1 {
		t.Errorf("user from userinfo email: %d", n)
	}
}

func TestLoginUnverifiedEmailRefused(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	lh.idp.SetUser(oidctest.User{Subject: "u", Email: "u@example.com", EmailVerified: false})
	b := oidctest.NewBrowser(t)
	end := last(lh.login(b, ""))
	if end.Status != http.StatusForbidden {
		t.Fatalf("status %d", end.Status)
	}
	assertNoLeak(t, end.Body)
	if n := lh.count(countRealUsers); n != 0 {
		t.Errorf("users = %d", n)
	}
}

func TestLoginLinksVerifiedEmailToExistingUser(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	if _, err := lh.db.Exec(`INSERT INTO users (id, email, name) VALUES ('existing', 'bob@example.com', 'Bob')`); err != nil {
		t.Fatal(err)
	}
	lh.idp.SetUser(oidctest.User{Subject: "bob-sub", Email: "bob@example.com", EmailVerified: true})
	b := oidctest.NewBrowser(t)
	end := last(lh.login(b, ""))
	if end.Body != "user=existing" {
		t.Fatalf("login ended %d %q", end.Status, end.Body)
	}
	if n := lh.count(`SELECT COUNT(*) FROM audit_log WHERE action = 'identity.linked_by_email' AND actor_id = 'existing'`); n != 1 {
		t.Errorf("audit rows = %d, want 1", n)
	}
}

func TestLoginNeverLinksSentinelUser(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	lh.idp.SetUser(oidctest.User{Subject: "x", Email: "former-member@local", EmailVerified: true})
	end := last(lh.login(oidctest.NewBrowser(t), ""))
	if end.Status != http.StatusForbidden {
		t.Fatalf("sentinel email login: %d %q", end.Status, end.Body)
	}
	if n := lh.count(`SELECT COUNT(*) FROM identities`); n != 0 {
		t.Errorf("identities = %d", n)
	}
}

func TestLoginRotatesPresentedSession(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	b := oidctest.NewBrowser(t)
	lh.login(b, "")
	old := lh.sessionCookie(b)
	if old == "" {
		t.Fatal("no session after first login")
	}
	// Re-login in the same browser: the old cookie is presented at callback.
	if end := last(lh.login(b, "")); end.Status != http.StatusOK {
		t.Fatalf("re-login %d %q", end.Status, end.Body)
	}
	nw := lh.sessionCookie(b)
	if nw == "" || nw == old {
		t.Fatalf("session not rotated: old=%q new=%q", old, nw)
	}
	if n := lh.count(`SELECT COUNT(*) FROM sessions WHERE token_hash = ?`, tokenHash(old)); n != 0 {
		t.Errorf("old session still present")
	}
	if n := lh.count(`SELECT COUNT(*) FROM sessions`); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}
}

func TestLogoutRevokesAndClears(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	b := oidctest.NewBrowser(t)
	lh.login(b, "")
	raw := lh.sessionCookie(b)

	// Without a CSRF token: refused, session intact.
	req, _ := http.NewRequest(http.MethodPost, lh.app.URL+"/auth/logout", nil)
	resp, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("logout without CSRF: %d, want 403", resp.StatusCode)
	}
	if n := lh.count(`SELECT COUNT(*) FROM sessions WHERE token_hash = ?`, tokenHash(raw)); n != 1 {
		t.Fatal("session revoked without CSRF token")
	}

	form := url.Values{auth.CSRFFormField: {auth.CSRFToken(testSessionSecret, tokenHash(raw))}}
	req, _ = http.NewRequest(http.MethodPost, lh.app.URL+"/auth/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Errorf("logout: %d → %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if n := lh.count(`SELECT COUNT(*) FROM sessions WHERE token_hash = ?`, tokenHash(raw)); n != 0 {
		t.Error("session not revoked")
	}
	clearedCookie := false
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName && c.MaxAge < 0 && c.Secure {
			clearedCookie = true
		}
	}
	if !clearedCookie {
		t.Errorf("session cookie not cleared: %v", resp.Header.Values("Set-Cookie"))
	}
	// The old token no longer authenticates.
	b2 := oidctest.NewBrowser(t)
	b2.SetCookie(lh.app.URL, &http.Cookie{Name: auth.CookieName, Value: raw})
	if status, _ := lh.get(b2, lh.app.URL+"/app"); status != http.StatusUnauthorized {
		t.Errorf("revoked session still works: %d", status)
	}
}

func TestDeletedUserSessionAndLoginRejected(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	b := oidctest.NewBrowser(t)
	end := last(lh.login(b, ""))
	userID := strings.TrimPrefix(end.Body, "user=")
	if status, _ := lh.get(b, lh.app.URL+"/app"); status != http.StatusOK {
		t.Fatalf("session should work before deletion: %d", status)
	}
	if _, err := lh.db.Exec(`UPDATE users SET deleted_at = '2026-10-03T00:00:00.000Z' WHERE id = ?`, userID); err != nil {
		t.Fatal(err)
	}
	if status, _ := lh.get(b, lh.app.URL+"/app"); status != http.StatusUnauthorized {
		t.Errorf("deleted user's session accepted: %d", status)
	}
	end = last(lh.login(oidctest.NewBrowser(t), ""))
	if end.Status != http.StatusForbidden {
		t.Errorf("deleted user login: %d, want 403", end.Status)
	}
	assertNoLeak(t, end.Body)
}

func TestLoginConcurrent(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	const distinct, repeats = 6, 3
	for i := 0; i < distinct; i++ {
		lh.idp.AddUser(fmt.Sprintf("u%d", i), oidctest.User{
			Subject: fmt.Sprintf("sub-%d", i), Email: fmt.Sprintf("u%d@example.com", i), EmailVerified: true,
		})
	}
	var wg sync.WaitGroup
	errs := make(chan string, distinct*repeats)
	for i := 0; i < distinct; i++ {
		for j := 0; j < repeats; j++ {
			wg.Add(1)
			go func(hint string) {
				defer wg.Done()
				b := oidctest.NewBrowser(t)
				steps, err := b.Follow(lh.app.URL+"/auth/google?login_hint="+hint, 5, nil)
				if err != nil {
					errs <- err.Error()
					return
				}
				if end := last(steps); end.Status != http.StatusOK {
					errs <- fmt.Sprintf("%s: %d %q", hint, end.Status, end.Body)
				}
			}(fmt.Sprintf("u%d", i))
		}
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if n := lh.count(countRealUsers); n != distinct {
		t.Errorf("users = %d, want %d", n, distinct)
	}
	if n := lh.count(`SELECT COUNT(*) FROM identities`); n != distinct {
		t.Errorf("identities = %d, want %d", n, distinct)
	}
	if n := lh.count(`SELECT COUNT(*) FROM sessions`); n != distinct*repeats {
		t.Errorf("sessions = %d, want %d", n, distinct*repeats)
	}
}

func TestLoginBootstrapGate(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{notBootstrapped: true, adminEmails: []string{"admin@example.com"}})

	lh.idp.SetUser(oidctest.User{Subject: "rando", Email: "rando@example.com", EmailVerified: true})
	end := last(lh.login(oidctest.NewBrowser(t), ""))
	if end.Status != http.StatusForbidden {
		t.Fatalf("non-admin before bootstrap: %d", end.Status)
	}
	assertNoLeak(t, end.Body)
	if n := lh.count(countRealUsers); n != 0 {
		t.Errorf("users = %d after refused bootstrap", n)
	}

	lh.idp.SetUser(oidctest.User{Subject: "admin", Email: "admin@example.com", EmailVerified: true})
	end = last(lh.login(oidctest.NewBrowser(t), ""))
	if end.Status != http.StatusOK {
		t.Fatalf("admin bootstrap: %d %q", end.Status, end.Body)
	}
	adminID := strings.TrimPrefix(end.Body, "user=")
	if n := lh.count(`SELECT bootstrap_done FROM platform_settings`); n != 1 {
		t.Error("bootstrap_done not set")
	}
	if n := lh.count(`SELECT COUNT(*) FROM memberships WHERE org_id = ? AND actor_id = ? AND role_id = ?`,
		perm.PlatformOrg, adminID, perm.PlatformOwnerRole); n != 1 {
		t.Errorf("platform owner memberships = %d", n)
	}
	// Second admin login stays idempotent.
	if end := last(lh.login(oidctest.NewBrowser(t), "")); end.Status != http.StatusOK {
		t.Fatalf("admin second login: %d", end.Status)
	}
	if n := lh.count(`SELECT COUNT(*) FROM memberships WHERE actor_id = ?`, adminID); n != 1 {
		t.Errorf("memberships = %d after second login", n)
	}
	// After bootstrap, others may sign up.
	lh.idp.SetUser(oidctest.User{Subject: "rando", Email: "rando@example.com", EmailVerified: true})
	if end := last(lh.login(oidctest.NewBrowser(t), "")); end.Status != http.StatusOK {
		t.Errorf("non-admin after bootstrap: %d", end.Status)
	}
}

func TestLoginUnknownProvider404(t *testing.T) {
	lh := newLoginHarness(t, harnessOpts{})
	b := oidctest.NewBrowser(t)
	if status, _ := lh.get(b, lh.app.URL+"/auth/nope"); status != http.StatusNotFound {
		t.Errorf("unknown provider: %d", status)
	}
}

func TestLoginDiscoveryFailureIsGeneric(t *testing.T) {
	// Google pointed at a dead issuer: discovery fails at Begin.
	d := dbtest.New(t)
	h, err := auth.NewHandler(auth.HandlerConfig{
		DB: d, Sessions: auth.NewSessionStore(d), SecretKey: "k", BaseURL: "http://app.test",
		Connectors: []auth.Connector{authidp.NewGoogleConnector("http://127.0.0.1:1", "id", "SECRET-VALUE", "http://app.test", nil)},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	h.Routes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/google", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status %d", rec.Code)
	}
	assertNoLeak(t, rec.Body.String(), "SECRET-VALUE")
}
