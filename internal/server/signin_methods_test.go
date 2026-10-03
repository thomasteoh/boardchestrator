package server_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/perm"
	"github.com/thomasteoh/boardchestrator/internal/server"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
	"github.com/thomasteoh/boardchestrator/internal/web"
)

// WU-604: linking policy, sign-up policy and Settings -> Sign-in methods,
// end to end through the production wiring against oidctest IdPs: "google"
// (env-seeded, trusted) and "corp" (BC_OIDC_CORP_*, policy per test).

const smSessionSecret = "0123456789abcdef0123456789abcdef"

type smHarness struct {
	t      *testing.T
	db     *sql.DB
	app    *httptest.Server
	google *oidctest.Server
	corp   *oidctest.Server
}

type smOpts struct {
	corpTrust, corpSignup bool
	unclaimed             bool // platform not bootstrapped
	adminEmails           []string
}

func newSMHarness(t *testing.T, o smOpts) *smHarness {
	t.Helper()
	d := dbtest.New(t)
	if !o.unclaimed {
		if _, err := d.Exec(`UPDATE platform_settings SET bootstrap_done = 1`); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO users (id, email, name) VALUES ('u-bob','bob@example.com','Bob'),('u-alice','alice@example.com','Alice'),('u-admin','admin@example.com','Admin')`,
		`INSERT INTO identities (id, user_id, provider, subject, email) VALUES ('i-bob-g','u-bob','google','bob-g','bob@example.com'),('i-alice-c','u-alice','corp','shared-sub','alice@corp.example')`,
		`INSERT INTO orgs (id, name, slug) VALUES ('org-acme','Acme Pty Ltd','acme')`,
		`INSERT INTO roles (id, org_id, name, is_system, grants_json) VALUES ('r-member','org-acme','Member',0,'["task.*"]')`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	g, c := oidctest.New(t), oidctest.New(t)
	var h http.Handler
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(app.Close)

	trust, signup := o.corpTrust, o.corpSignup
	cfg := testConfig()
	cfg.SessionSecret = smSessionSecret
	cfg.BaseURL = app.URL
	cfg.AllowSignup = true
	cfg.AdminEmails = o.adminEmails
	// These tests sign in many times from 127.0.0.1; the sign-in rate limit
	// has its own tests (WU-605).
	cfg.SignInRateLimit = config.RateLimit{PerMinute: 6000, Burst: 1000}
	cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.GoogleIssuer = g.ClientID, g.ClientSecret, g.Issuer()
	cfg.OIDCProviders = []config.OIDCEnvProvider{{
		ID: "corp", Issuer: c.Issuer(), ClientID: c.ClientID, ClientSecret: c.ClientSecret,
		Preset: "generic", DisplayName: "Corp", TrustEmail: &trust, AllowSignup: &signup,
	}}
	s := server.NewWithDB(cfg, d)
	// Start (not run here) creates the dispatcher; wire an equivalent one.
	web.SetDispatcher(action.New(d,
		action.WithScopeResolver(action.NewDBScopeResolver(d)),
		action.WithPermissionChecker(perm.NewCheckerAdapter(d)),
		action.WithSecretKey(tenant.PadKey(cfg.SecretKey)),
	))
	h = s
	return &smHarness{t: t, db: d, app: app, google: g, corp: c}
}

// signedIn gives b a fresh session for userID and returns its CSRF token.
func (h *smHarness) signedIn(b *oidctest.Browser, userID string) (raw, csrf string) {
	h.t.Helper()
	raw, sess, err := auth.NewSessionStore(h.db).Create(context.Background(), userID, "", "")
	if err != nil {
		h.t.Fatal(err)
	}
	b.SetCookie(h.app.URL, &http.Cookie{Name: auth.CookieName, Value: raw})
	return raw, auth.CSRFToken(smSessionSecret, sess.TokenHash)
}

func (h *smHarness) post(b *oidctest.Browser, path, csrf string) *http.Response {
	h.t.Helper()
	form := url.Values{auth.CSRFFormField: {csrf}}
	req, _ := http.NewRequest(http.MethodPost, h.app.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func (h *smHarness) follow(b *oidctest.Browser, u string) oidctest.Step {
	h.t.Helper()
	if strings.HasPrefix(u, "/") {
		u = h.app.URL + u
	}
	steps, err := b.Follow(u, 8, nil)
	if err != nil {
		h.t.Fatalf("follow %s: %v (%+v)", u, err, steps)
	}
	return steps[len(steps)-1]
}

func (h *smHarness) n(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(q, args...).Scan(&n); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// startLink posts the link button and returns the IdP authorize URL.
func (h *smHarness) startLink(b *oidctest.Browser, provider, csrf string) string {
	h.t.Helper()
	resp := h.post(b, "/settings/sign-in-methods/link/"+provider, csrf)
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("link begin status %d", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// invite inserts an invite for email and returns its raw token.
func (h *smHarness) invite(email, expires string, accepted bool) string {
	h.t.Helper()
	token := "tok-" + strings.NewReplacer("@", "-", ".", "-").Replace(email)
	sum := sha256.Sum256([]byte(token))
	var acc any
	if accepted {
		acc = "2026-01-01T00:00:00.000Z"
	}
	if _, err := h.db.Exec(`INSERT INTO invites (id, org_id, inviter_id, email, token_hash, role_id, resource_type, resource_id, expires_at, accepted_at)
		VALUES (?, 'org-acme', 'u-admin', ?, ?, 'r-member', 'org', 'org-acme', ?, ?)`,
		"inv-"+email, email, hex.EncodeToString(sum[:]), expires, acc); err != nil {
		h.t.Fatal(err)
	}
	return token
}

func future() string { return time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02T15:04:05.000Z") }

const realUsers = `SELECT COUNT(*) FROM users WHERE id <> 'ffffffffffffffffffffffffffffffff'`

func TestEmailLinkRequiresTrustedProvider(t *testing.T) {
	// Untrusted: a verified email matching an existing user neither links nor
	// creates anything, even with open sign-up, and the page says only "no
	// account".
	h := newSMHarness(t, smOpts{corpTrust: false, corpSignup: true})
	h.corp.SetUser(oidctest.User{Subject: "bob-corp", Email: "bob@example.com", EmailVerified: true})
	users := h.n(realUsers)
	end := h.follow(oidctest.NewBrowser(t), "/auth/corp")
	if end.Status != http.StatusForbidden || !strings.Contains(end.Body, "no account for this email") ||
		!strings.Contains(end.Body, "organisation admin for an invite") {
		t.Fatalf("untrusted email link: %d %q", end.Status, end.Body)
	}
	if strings.Contains(end.Body, "bob@example.com") {
		t.Error("refusal page echoes the email")
	}
	if n := h.n(`SELECT COUNT(*) FROM identities WHERE provider='corp' AND subject='bob-corp'`); n != 0 {
		t.Errorf("untrusted provider linked by email (%d identities)", n)
	}
	if n := h.n(realUsers); n != users {
		t.Errorf("users %d -> %d", users, n)
	}
	if n := h.n(`SELECT COUNT(*) FROM sessions`); n != 0 {
		t.Errorf("sessions = %d", n)
	}

	// Trusted: the same assertion links to Bob.
	h2 := newSMHarness(t, smOpts{corpTrust: true})
	h2.corp.SetUser(oidctest.User{Subject: "bob-corp", Email: "bob@example.com", EmailVerified: true})
	b := oidctest.NewBrowser(t)
	if end := h2.follow(b, "/auth/corp"); end.Status != http.StatusOK {
		t.Fatalf("trusted email link: %d %q", end.Status, end.Body)
	}
	if n := h2.n(`SELECT COUNT(*) FROM identities WHERE provider='corp' AND subject='bob-corp' AND user_id='u-bob'`); n != 1 {
		t.Fatal("trusted provider did not link by verified email")
	}
	if n := h2.n(`SELECT COUNT(*) FROM audit_log WHERE action='identity.linked_by_email' AND actor_id='u-bob'`); n != 1 {
		t.Errorf("identity.linked_by_email audit rows = %d", n)
	}

	// Trusted but unverified: no link.
	h3 := newSMHarness(t, smOpts{corpTrust: true, corpSignup: true})
	h3.corp.SetUser(oidctest.User{Subject: "bob-corp", Email: "bob@example.com", EmailVerified: false})
	if end := h3.follow(oidctest.NewBrowser(t), "/auth/corp"); end.Status != http.StatusForbidden {
		t.Fatalf("unverified email: %d", end.Status)
	}
	if n := h3.n(`SELECT COUNT(*) FROM identities WHERE provider='corp' AND subject='bob-corp'`); n != 0 {
		t.Error("unverified email linked")
	}
}

func TestExplicitLinkFromSettings(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	b := oidctest.NewBrowser(t)
	raw, csrf := h.signedIn(b, "u-bob")

	page := h.follow(b, "/settings/sign-in-methods")
	if page.Status != http.StatusOK || !strings.Contains(page.Body, "Link Corp") || !strings.Contains(page.Body, "Google") {
		t.Fatalf("settings page: %d %q", page.Status, page.Body)
	}
	if !strings.Contains(page.Body, "disabled") {
		t.Error("the only method's unlink button is not disabled")
	}

	// Explicit links ignore email: the corp account has a different,
	// unverified address and corp is untrusted with sign-up closed.
	h.corp.SetUser(oidctest.User{Subject: "bob-corp", Email: "robert@corp.example", EmailVerified: false})
	authz := h.startLink(b, "corp", csrf)
	if !strings.HasPrefix(authz, h.corp.Issuer()) {
		t.Fatalf("link did not go to the corp IdP: %s", authz)
	}
	end := h.follow(b, authz)
	if end.Status != http.StatusOK || !strings.Contains(end.URL, "/settings/sign-in-methods?notice=linked") ||
		!strings.Contains(end.Body, "Sign-in method linked") {
		t.Fatalf("link ended %d %s %q", end.Status, end.URL, end.Body)
	}
	if n := h.n(`SELECT COUNT(*) FROM identities WHERE provider='corp' AND subject='bob-corp' AND user_id='u-bob' AND created_at IS NOT NULL`); n != 1 {
		t.Fatal("identity not linked to the session user")
	}
	if n := h.n(`SELECT COUNT(*) FROM audit_log WHERE action='identity.linked' AND actor_id='u-bob' AND subject='corp'`); n != 1 {
		t.Errorf("identity.linked audit rows = %d", n)
	}
	// Linking keeps the session: same cookie, no new session.
	if c := b.Cookie(h.app.URL, auth.CookieName); c == nil || c.Value != raw {
		t.Error("link replaced the session cookie")
	}
	if n := h.n(`SELECT COUNT(*) FROM sessions`); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}
	// Now both are listed, both unlinkable, nothing left to link.
	page = h.follow(b, "/settings/sign-in-methods")
	if strings.Contains(page.Body, "Link Corp") || strings.Contains(page.Body, "Link Google") || strings.Contains(page.Body, " disabled") {
		t.Errorf("page after link: %q", page.Body)
	}
}

func TestLinkRefusedFromRevokedSession(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	b := oidctest.NewBrowser(t)
	raw, csrf := h.signedIn(b, "u-bob")
	h.corp.SetUser(oidctest.User{Subject: "bob-corp", Email: "bob@example.com", EmailVerified: true})
	authz := h.startLink(b, "corp", csrf)
	if _, err := h.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hashOf(raw)); err != nil {
		t.Fatal(err)
	}
	steps, err := b.Follow(authz, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	var sawRefusal bool
	for _, s := range steps {
		sawRefusal = sawRefusal || strings.Contains(s.URL, "error=link_session")
	}
	if !sawRefusal {
		t.Errorf("no link_session refusal: %+v", steps)
	}
	if n := h.n(`SELECT COUNT(*) FROM identities WHERE provider='corp' AND subject='bob-corp'`); n != 0 {
		t.Fatal("identity linked from a revoked session")
	}
	if n := h.n(`SELECT COUNT(*) FROM sessions`); n != 0 {
		t.Errorf("a session was created (%d)", n)
	}

	// A different live session in the browser (signed in as Alice
	// mid-flow) does not satisfy Bob's link either.
	b2 := oidctest.NewBrowser(t)
	_, csrf2 := h.signedIn(b2, "u-bob")
	authz = h.startLink(b2, "corp", csrf2)
	h.signedIn(b2, "u-alice")
	if end := h.follow(b2, authz); !strings.Contains(end.URL, "error=link_session") {
		t.Errorf("link with a swapped session ended at %s", end.URL)
	}
	if n := h.n(`SELECT COUNT(*) FROM identities WHERE provider='corp' AND subject='bob-corp'`); n != 0 {
		t.Fatal("identity linked through a different session")
	}
}

func TestLinkRefusedForAnotherUsersIdentity(t *testing.T) {
	h := newSMHarness(t, smOpts{corpTrust: true, corpSignup: true})
	b := oidctest.NewBrowser(t)
	raw, csrf := h.signedIn(b, "u-bob")
	// Alice already owns corp/shared-sub.
	h.corp.SetUser(oidctest.User{Subject: "shared-sub", Email: "alice@corp.example", EmailVerified: true})
	end := h.follow(b, h.startLink(b, "corp", csrf))
	if !strings.Contains(end.URL, "error=identity_in_use") || !strings.Contains(end.Body, "already linked to a different account") {
		t.Fatalf("ended %d %s %q", end.Status, end.URL, end.Body)
	}
	if n := h.n(`SELECT COUNT(*) FROM identities WHERE subject='shared-sub' AND user_id='u-alice'`); n != 1 {
		t.Fatal("identity moved off its owner")
	}
	if c := b.Cookie(h.app.URL, auth.CookieName); c == nil || c.Value != raw {
		t.Error("session changed: the link must never sign in as the identity's owner")
	}
	if n := h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-alice'`); n != 0 {
		t.Error("a session was issued for the identity's owner")
	}
}

func TestSignupPolicy(t *testing.T) {
	h := newSMHarness(t, smOpts{corpTrust: false, corpSignup: false})
	users := h.n(realUsers)

	// No invite, allow_signup=0: refused.
	h.corp.SetUser(oidctest.User{Subject: "carol-sub", Email: "carol@corp.example", EmailVerified: true})
	end := h.follow(oidctest.NewBrowser(t), "/auth/corp")
	if end.Status != http.StatusForbidden || !strings.Contains(end.Body, "organisation admin for an invite") {
		t.Fatalf("closed sign-up: %d %q", end.Status, end.Body)
	}
	if n := h.n(realUsers); n != users {
		t.Fatal("user created without an invite")
	}

	// Tokens that grant nothing: unknown, expired, already used.
	h.invite("expired@corp.example", "2020-01-01T00:00:00.000Z", false)
	h.invite("used@corp.example", future(), true)
	for _, tok := range []string{"tok-nonexistent", "tok-expired-corp-example", "tok-used-corp-example"} {
		end := h.follow(oidctest.NewBrowser(t), "/auth/corp?invite="+tok)
		if end.Status != http.StatusForbidden {
			t.Errorf("invite %s: %d", tok, end.Status)
		}
		page := h.follow(oidctest.NewBrowser(t), "/login?invite="+tok)
		if !strings.Contains(page.Body, "invalid, has expired or has already been used") || strings.Contains(page.Body, "invite="+tok) {
			t.Errorf("login page for bad invite %s: %q", tok, page.Body)
		}
	}
	if n := h.n(realUsers); n != users {
		t.Fatal("an unusable invite granted sign-up")
	}

	// A valid invite: the anonymous invitee lands on /login with the invite
	// context, and signs up even though corp does not verify the email.
	tok := h.invite("carol@corp.example", future(), false)
	b := oidctest.NewBrowser(t)
	resp, err := b.Get(h.app.URL + "/invite/accept?token=" + tok)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/login?invite="+tok {
		t.Fatalf("anonymous invite landing: %d %s", resp.StatusCode, loc)
	}
	page := h.follow(b, "/login?invite="+tok)
	if !strings.Contains(page.Body, "Acme Pty Ltd") {
		t.Fatalf("login page lacks invite context: %q", page.Body)
	}
	href := extractHref(t, page.Body, "/auth/corp?")
	if !strings.Contains(href, "invite="+tok) {
		t.Fatalf("corp button does not carry the invite: %s", href)
	}
	h.corp.SetUser(oidctest.User{Subject: "carol-sub", Email: "carol@personal.example", EmailVerified: false, Name: "Carol"})
	end = h.follow(b, href)
	if end.Status != http.StatusOK || !strings.HasSuffix(strings.SplitN(end.URL, "?", 2)[0], "/app") {
		t.Fatalf("invite sign-up ended %d %s %q", end.Status, end.URL, end.Body)
	}
	var userID, email string
	if err := h.db.QueryRow(`SELECT u.id, u.email FROM users u JOIN identities i ON i.user_id = u.id
		WHERE i.provider='corp' AND i.subject='carol-sub' AND i.email='carol@personal.example'`).Scan(&userID, &email); err != nil {
		t.Fatalf("invitee not created: %v", err)
	}
	if email != "carol@corp.example" {
		t.Errorf("new user's email = %q, want the invite's", email)
	}
	if n := h.n(`SELECT COUNT(*) FROM memberships WHERE actor_id=? AND org_id='org-acme' AND role_id='r-member'`, userID); n != 1 {
		t.Errorf("invite membership rows = %d", n)
	}
	if n := h.n(`SELECT COUNT(*) FROM invites WHERE email='carol@corp.example' AND accepted_at IS NOT NULL`); n != 1 {
		t.Error("invite not accepted")
	}
	if n := h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.signup' AND actor_id=? AND detail_json LIKE '%"method":"invite"%'`, userID); n != 1 {
		t.Errorf("auth.signup audit rows = %d", n)
	}
	// The invite is spent: a second person cannot reuse it.
	h.corp.SetUser(oidctest.User{Subject: "mallory-sub", Email: "mallory@corp.example", EmailVerified: true})
	if end := h.follow(oidctest.NewBrowser(t), "/auth/corp?invite="+tok); end.Status != http.StatusForbidden {
		t.Errorf("spent invite reused: %d", end.Status)
	}

	assertAuditClean(t, h, tok, h.corp.ClientSecret, h.google.ClientSecret)
}

func TestOpenSignupAudited(t *testing.T) {
	h := newSMHarness(t, smOpts{corpSignup: true})
	h.corp.SetUser(oidctest.User{Subject: "dan-sub", Email: "dan@corp.example", EmailVerified: true})
	if end := h.follow(oidctest.NewBrowser(t), "/auth/corp"); end.Status != http.StatusOK {
		t.Fatalf("open sign-up: %d %q", end.Status, end.Body)
	}
	if n := h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.signup' AND detail_json LIKE '%"method":"open"%'`); n != 1 {
		t.Errorf("auth.signup open rows = %d", n)
	}
	// Open sign-up still needs a verified email.
	h.corp.SetUser(oidctest.User{Subject: "eve-sub", Email: "eve@corp.example", EmailVerified: false})
	if end := h.follow(oidctest.NewBrowser(t), "/auth/corp"); end.Status != http.StatusForbidden {
		t.Errorf("unverified open sign-up: %d", end.Status)
	}
}

func TestBootstrapSignupIgnoresClosedSignup(t *testing.T) {
	h := newSMHarness(t, smOpts{unclaimed: true, adminEmails: []string{"root@corp.example"}})
	h.corp.SetUser(oidctest.User{Subject: "root-sub", Email: "root@corp.example", EmailVerified: true})
	if end := h.follow(oidctest.NewBrowser(t), "/auth/corp"); end.Status != http.StatusOK {
		t.Fatalf("bootstrap sign-up: %d %q", end.Status, end.Body)
	}
	if n := h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.signup' AND detail_json LIKE '%"method":"bootstrap"%'`); n != 1 {
		t.Errorf("auth.signup bootstrap rows = %d", n)
	}
	if n := h.n(`SELECT bootstrap_done FROM platform_settings`); n != 1 {
		t.Error("platform not marked bootstrapped")
	}
	// Once claimed, the same closed provider refuses the next stranger.
	h.corp.SetUser(oidctest.User{Subject: "x-sub", Email: "x@corp.example", EmailVerified: true})
	if end := h.follow(oidctest.NewBrowser(t), "/auth/corp"); end.Status != http.StatusForbidden {
		t.Errorf("post-bootstrap closed sign-up: %d", end.Status)
	}
}

func TestUnlinkFromSettings(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	if _, err := h.db.Exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES ('i-bob-c','u-bob','corp','bob-c','bob@corp.example')`); err != nil {
		t.Fatal(err)
	}
	b := oidctest.NewBrowser(t)
	_, csrf := h.signedIn(b, "u-bob")

	// Someone else's identity: refused as not found, untouched.
	resp := h.post(b, "/settings/sign-in-methods/unlink/i-alice-c", csrf)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=not_found") {
		t.Errorf("unlink another user's identity -> %s", loc)
	}
	if n := h.n(`SELECT COUNT(*) FROM identities WHERE id='i-alice-c'`); n != 1 {
		t.Fatal("another user's identity was unlinked")
	}

	resp = h.post(b, "/settings/sign-in-methods/unlink/i-bob-c", csrf)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "notice=unlinked") {
		t.Fatalf("unlink -> %d %s", resp.StatusCode, loc)
	}
	if n := h.n(`SELECT COUNT(*) FROM identities WHERE id='i-bob-c'`); n != 0 {
		t.Fatal("identity not unlinked")
	}
	if n := h.n(`SELECT COUNT(*) FROM audit_log WHERE action='identity.unlinked' AND actor_id='u-bob' AND subject='corp'`); n != 1 {
		t.Errorf("identity.unlinked audit rows = %d", n)
	}

	// The last method stays.
	resp = h.post(b, "/settings/sign-in-methods/unlink/i-bob-g", csrf)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=last_method") {
		t.Errorf("last-method unlink -> %s", loc)
	}
	if n := h.n(`SELECT COUNT(*) FROM identities WHERE id='i-bob-g'`); n != 1 {
		t.Fatal("last sign-in method was unlinked")
	}
	page := h.follow(b, "/settings/sign-in-methods?error=last_method")
	if !strings.Contains(page.Body, "only sign-in method") || !strings.Contains(page.Body, "disabled") {
		t.Errorf("page: %q", page.Body)
	}
	// Without CSRF nothing happens.
	if resp := h.post(b, "/settings/sign-in-methods/unlink/i-bob-g", "bad"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("unlink without CSRF: %d", resp.StatusCode)
	}
	if resp := h.post(b, "/settings/sign-in-methods/link/corp", "bad"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("link without CSRF: %d", resp.StatusCode)
	}
	assertAuditClean(t, h, h.corp.ClientSecret, h.google.ClientSecret)
}

func TestSignInMethodsPageNeedsSession(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	resp, err := oidctest.NewBrowser(t).Get(h.app.URL + "/settings/sign-in-methods")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/login?return_to=") {
		t.Errorf("anonymous: %d %s", resp.StatusCode, loc)
	}
}

// assertAuditClean fails if any audit row carries one of the secrets.
func assertAuditClean(t *testing.T, h *smHarness, secrets ...string) {
	t.Helper()
	rows, err := h.db.Query(`SELECT action, subject, detail_json FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a, s, d string
		if err := rows.Scan(&a, &s, &d); err != nil {
			t.Fatal(err)
		}
		for _, sec := range secrets {
			if sec != "" && (strings.Contains(d, sec) || strings.Contains(s, sec)) {
				t.Errorf("audit %s carries a secret: %s", a, d)
			}
		}
		for _, k := range []string{"token_enc", "id_token", "access_token", "client_secret"} {
			if strings.Contains(d, k) {
				t.Errorf("audit %s detail has %s: %s", a, k, d)
			}
		}
	}
}

func hashOf(raw string) string {
	s := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(s[:])
}

// extractHref returns the first href in body starting with prefix, unescaped.
func extractHref(t *testing.T, body, prefix string) string {
	t.Helper()
	i := strings.Index(body, `href="`+prefix)
	if i < 0 {
		t.Fatalf("no href %s in %q", prefix, body)
	}
	rest := body[i+len(`href="`):]
	v := rest[:strings.IndexByte(rest, '"')]
	return strings.ReplaceAll(v, "&amp;", "&")
}
