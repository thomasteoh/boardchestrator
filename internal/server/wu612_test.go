package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/auth/passkey/passkeytest"
)

// WU-612: passkeys end to end through the production wiring, with a
// software authenticator playing the browser. BC_BASE_URL is on localhost
// (an IP address cannot be a WebAuthn RP ID).

type pkHarness struct {
	*smHarness
	base string
}

func newPKHarness(t *testing.T, o smOpts) *pkHarness {
	t.Helper()
	o.localhost = true
	h := newSMHarness(t, o)
	return &pkHarness{smHarness: h, base: strings.Replace(h.app.URL, "127.0.0.1", "localhost", 1)}
}

func (h *pkHarness) do(b *oidctest.Browser, method, path string, body []byte, hdr map[string]string) (int, []byte) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, h.base+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (h *pkHarness) form(b *oidctest.Browser, path, csrf string, v url.Values) *http.Response {
	h.t.Helper()
	if v == nil {
		v = url.Values{}
	}
	v.Set(auth.CSRFFormField, csrf)
	req, _ := http.NewRequest(http.MethodPost, h.base+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

// session gives b a session for userID on the localhost base.
func (h *pkHarness) session(b *oidctest.Browser, userID string) string {
	h.t.Helper()
	raw, csrf := h.signedIn(oidctest.NewBrowser(h.t), userID)
	b.SetCookie(h.base, &http.Cookie{Name: auth.CookieName, Value: raw})
	return csrf
}

// add registers a passkey for b's signed-in user.
func (h *pkHarness) add(b *oidctest.Browser, a *passkeytest.Authenticator, csrf string, o passkeytest.Options) (int, map[string]string) {
	h.t.Helper()
	hdr := map[string]string{auth.CSRFHeader: csrf}
	st, opts := h.do(b, http.MethodPost, "/settings/passkeys/begin", []byte(`{}`), hdr)
	if st != http.StatusOK {
		h.t.Fatalf("add begin: %d %s", st, opts)
	}
	body, _, err := a.Create(opts, h.base, o)
	if err != nil {
		h.t.Fatal(err)
	}
	st, out := h.do(b, http.MethodPost, "/settings/passkeys/finish", body, hdr)
	return st, decode(h.t, out)
}

// login runs a usernameless sign-in.
func (h *pkHarness) login(b *oidctest.Browser, a *passkeytest.Authenticator, o passkeytest.Options) (int, map[string]string) {
	h.t.Helper()
	st, opts := h.do(b, http.MethodGet, "/auth/passkey/login/begin", nil, nil)
	if st != http.StatusOK {
		h.t.Fatalf("login begin: %d %s", st, opts)
	}
	body, err := a.Get(opts, h.base, o)
	if err != nil {
		h.t.Fatal(err)
	}
	st, out := h.do(b, http.MethodPost, "/auth/passkey/login/finish", body, nil)
	return st, decode(h.t, out)
}

// signup runs first-method registration with query q.
func (h *pkHarness) signup(b *oidctest.Browser, a *passkeytest.Authenticator, q url.Values) (int, map[string]string) {
	h.t.Helper()
	st, opts := h.do(b, http.MethodGet, "/auth/passkey/signup/begin?"+q.Encode(), nil, nil)
	if st != http.StatusOK {
		return st, decode(h.t, opts)
	}
	body, _, err := a.Create(opts, h.base, passkeytest.Options{})
	if err != nil {
		h.t.Fatal(err)
	}
	st, out := h.do(b, http.MethodPost, "/auth/passkey/signup/finish", body, nil)
	return st, decode(h.t, out)
}

func decode(t *testing.T, b []byte) map[string]string {
	t.Helper()
	m := map[string]string{}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// sessionUser is the user b's session cookie belongs to ("" = none).
func (h *pkHarness) sessionUser(b *oidctest.Browser) (user, provider string) {
	h.t.Helper()
	c := b.Cookie(h.base, auth.CookieName)
	if c == nil {
		return "", ""
	}
	sess, err := auth.NewSessionStore(h.db).Lookup(h.t.Context(), c.Value)
	if err != nil {
		return "", ""
	}
	return sess.UserID, sess.ProviderID
}

func TestPasskeyRegisterAndUsernamelessLogin(t *testing.T) {
	h := newPKHarness(t, smOpts{})
	a := passkeytest.New()
	bob := oidctest.NewBrowser(t)
	csrf := h.session(bob, "u-bob")

	st, out := h.add(bob, a, csrf, passkeytest.Options{})
	if st != http.StatusOK || out["redirect"] != "/settings/sign-in-methods?notice=passkey_added" {
		t.Fatalf("add: %d %v", st, out)
	}
	var name, handle string
	if err := h.db.QueryRow(`SELECT c.name, hex(u.webauthn_handle) FROM webauthn_credentials c JOIN users u ON u.id = c.user_id WHERE c.user_id='u-bob'`).Scan(&name, &handle); err != nil {
		t.Fatal(err)
	}
	if name != "iCloud Keychain" || len(handle) != 64 {
		t.Fatalf("stored passkey name %q handle %q", name, handle)
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='passkey.registered' AND actor_id='u-bob'`) != 1 {
		t.Fatal("passkey.registered not audited")
	}

	// Usernameless sign-in from a fresh browser.
	nb := oidctest.NewBrowser(t)
	st, out = h.login(nb, a, passkeytest.Options{})
	if st != http.StatusOK || out["redirect"] != "/app" {
		t.Fatalf("login: %d %v", st, out)
	}
	if u, p := h.sessionUser(nb); u != "u-bob" || p != auth.PasskeyProviderID {
		t.Fatalf("session user %q provider %q", u, p)
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-bob' AND auth_method='passkey'`) != 1 {
		t.Fatal("no passkey session")
	}
	if h.n(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id='u-bob' AND sign_count=1 AND last_used_at IS NOT NULL`) != 1 {
		t.Fatal("credential not updated")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.login' AND actor_id='u-bob' AND json_extract(detail_json,'$.method')='passkey'`) != 1 {
		t.Fatal("auth.login not audited")
	}

	// Session rotation: signing in again with the passkey revokes the
	// session the browser presented.
	old := nb.Cookie(h.base, auth.CookieName).Value
	if st, _ := h.login(nb, a, passkeytest.Options{}); st != http.StatusOK {
		t.Fatalf("second login: %d", st)
	}
	if _, err := auth.NewSessionStore(h.db).Lookup(t.Context(), old); err == nil {
		t.Fatal("presented session not revoked")
	}

	// The Sign-in methods page lists it.
	st, page := h.do(bob, http.MethodGet, "/settings/sign-in-methods", nil, nil)
	if st != http.StatusOK || !strings.Contains(string(page), "iCloud Keychain") || !strings.Contains(string(page), `data-bc-passkey="add"`) {
		t.Fatalf("sign-in methods page: %d", st)
	}
	// /login offers passkey sign-in.
	st, page = h.do(oidctest.NewBrowser(t), http.MethodGet, "/login", nil, nil)
	if st != http.StatusOK || !strings.Contains(string(page), `data-bc-passkey="login"`) || !strings.Contains(string(page), "passkey.") {
		t.Fatalf("login page: %d", st)
	}
}

func TestPasskeyAddNeedsSessionAndCSRF(t *testing.T) {
	h := newPKHarness(t, smOpts{})
	b := oidctest.NewBrowser(t)
	if st, _ := h.do(b, http.MethodPost, "/settings/passkeys/begin", []byte(`{}`), nil); st != http.StatusForbidden {
		t.Fatalf("anonymous begin: %d", st)
	}
	h.session(b, "u-bob")
	if st, _ := h.do(b, http.MethodPost, "/settings/passkeys/begin", []byte(`{}`), nil); st != http.StatusForbidden {
		t.Fatalf("begin without CSRF: %d", st)
	}
	// A ceremony begun by one session cannot be finished by another.
	a := passkeytest.New()
	csrf := h.session(b, "u-bob")
	st, opts := h.do(b, http.MethodPost, "/settings/passkeys/begin", []byte(`{}`), map[string]string{auth.CSRFHeader: csrf})
	if st != http.StatusOK {
		t.Fatalf("begin: %d", st)
	}
	body, _, err := a.Create(opts, h.base, passkeytest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	csrf2 := h.session(b, "u-bob") // new session, same flow cookie
	st, out := h.do(b, http.MethodPost, "/settings/passkeys/finish", body, map[string]string{auth.CSRFHeader: csrf2})
	if st != http.StatusForbidden || h.n(`SELECT COUNT(*) FROM webauthn_credentials`) != 0 {
		t.Fatalf("finish from another session: %d %v", st, decode(t, out))
	}
}

func TestPasskeyLoginForgeriesRefused(t *testing.T) {
	h := newPKHarness(t, smOpts{})
	a := passkeytest.New()
	bob := oidctest.NewBrowser(t)
	if st, _ := h.add(bob, a, h.session(bob, "u-bob"), passkeytest.Options{}); st != http.StatusOK {
		t.Fatal("add")
	}
	for name, o := range map[string]passkeytest.Options{
		"wrong origin":    {Origin: "https://evil.example.com"},
		"wrong rp id":     {RPID: "evil.example.com"},
		"wrong challenge": {Challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"no user present": {NoUP: true},
		"bad signature":   {BadSignature: true},
		"other handle":    {UserHandle: []byte("not bob's handle")},
		"no user verified (latched)": {NoUV: true},
	} {
		b := oidctest.NewBrowser(t)
		st, out := h.login(b, a, o)
		if st != http.StatusForbidden || out["error"] == "" || out["ref"] == "" {
			t.Errorf("%s: %d %v", name, st, out)
		}
		if u, _ := h.sessionUser(b); u != "" {
			t.Errorf("%s: signed in as %s", name, u)
		}
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE auth_method='passkey'`) != 0 {
		t.Fatal("a forged assertion made a session")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.login_failed' AND json_extract(detail_json,'$.provider')='passkey'`) < 7 {
		t.Fatal("failures not audited")
	}
	// No flow cookie: refused.
	opts := []byte(`{"publicKey":{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","rpId":"localhost"}}`)
	body, err := a.Get(opts, h.base, passkeytest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := h.do(oidctest.NewBrowser(t), http.MethodPost, "/auth/passkey/login/finish", body, nil); st != http.StatusBadRequest {
		t.Fatalf("no flow cookie: %d", st)
	}
	// Unknown credential.
	if st, out := h.login(oidctest.NewBrowser(t), passkeytestWith(t, h, a), passkeytest.Options{}); st != http.StatusForbidden {
		t.Fatalf("unknown credential: %d %v", st, out)
	}
}

// passkeytestWith returns an authenticator holding a credential the server
// never registered (created against fresh options).
func passkeytestWith(t *testing.T, h *pkHarness, _ *passkeytest.Authenticator) *passkeytest.Authenticator {
	t.Helper()
	o := passkeytest.New()
	opts := []byte(`{"publicKey":{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","rp":{"id":"localhost"},"user":{"id":"AAAA"}}}`)
	if _, _, err := o.Create(opts, h.base, passkeytest.Options{}); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestPasskeySignCountRegressionAndReplay(t *testing.T) {
	h := newPKHarness(t, smOpts{})
	a := passkeytest.New()
	bob := oidctest.NewBrowser(t)
	if st, _ := h.add(bob, a, h.session(bob, "u-bob"), passkeytest.Options{}); st != http.StatusOK {
		t.Fatal("add")
	}
	if st, _ := h.login(oidctest.NewBrowser(t), a, passkeytest.Options{}); st != http.StatusOK {
		t.Fatal("first login")
	}
	// Stored count is now 1; a clone reporting 1 (or less) is refused.
	for _, c := range []uint32{1, 0} {
		c := c
		st, out := h.login(oidctest.NewBrowser(t), a, passkeytest.Options{SignCount: &c})
		if st != http.StatusForbidden || !strings.Contains(out["error"], "looks like a copy") {
			t.Fatalf("count %d: %d %v", c, st, out)
		}
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.passkey_clone_suspected' AND actor_id='u-bob'`) != 2 {
		t.Fatal("clone not audited")
	}
	if h.n(`SELECT COUNT(*) FROM webauthn_credentials WHERE sign_count=1`) != 1 {
		t.Fatal("count changed by a refused assertion")
	}

	// Replay: a synced passkey (counter always 0) whose verified response
	// is posted again with a copy of the flow cookie.
	carol := oidctest.NewBrowser(t)
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-carol','carol@example.com','Carol')`)
	h.exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES ('i-carol','u-carol','google','carol-g','carol@example.com')`)
	sa := passkeytest.New()
	sa.CountStep, sa.Synced = 0, true
	if st, _ := h.add(carol, sa, h.session(carol, "u-carol"), passkeytest.Options{}); st != http.StatusOK {
		t.Fatal("add synced")
	}
	b := oidctest.NewBrowser(t)
	st, opts := h.do(b, http.MethodGet, "/auth/passkey/login/begin", nil, nil)
	if st != http.StatusOK {
		t.Fatal("begin")
	}
	flow := *b.Cookie(h.base, auth.FlowCookieName)
	body, err := sa.Get(opts, h.base, passkeytest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if st, out := h.do(b, http.MethodPost, "/auth/passkey/login/finish", body, nil); st != http.StatusOK {
		t.Fatalf("synced login: %d %s", st, out)
	}
	attacker := oidctest.NewBrowser(t)
	attacker.SetCookie(h.base, &flow)
	if st, out := h.do(attacker, http.MethodPost, "/auth/passkey/login/finish", body, nil); st != http.StatusForbidden {
		t.Fatalf("replay: %d %s", st, out)
	}
	if u, _ := h.sessionUser(attacker); u != "" {
		t.Fatal("replay signed in")
	}
}

func TestPasskeySignupWithInvite(t *testing.T) {
	h := newPKHarness(t, smOpts{})
	tok := h.invite("dana@example.com", future(), false)
	a := passkeytest.New()

	// No token, an unknown token, a used token: refused, nothing created.
	used := h.invite("used@example.com", future(), true)
	for _, q := range []url.Values{
		{"name": {"Dana"}},
		{"name": {"Dana"}, "invite": {"tok-nope"}},
		{"name": {"Dana"}, "invite": {used}},
		{"name": {"Dana"}, "bootstrap": {"1"}, "email": {"dana@example.com"}},
	} {
		st, out := h.signup(oidctest.NewBrowser(t), a, q)
		if st != http.StatusForbidden || out["error"] == "" {
			t.Errorf("signup %v: %d %v", q, st, out)
		}
	}
	if h.n(`SELECT COUNT(*) FROM users WHERE email='dana@example.com'`) != 0 {
		t.Fatal("user created without a valid invite")
	}
	// A missing name is refused before anything else.
	if st, _ := h.signup(oidctest.NewBrowser(t), a, url.Values{"invite": {tok}}); st != http.StatusBadRequest {
		t.Fatalf("no name: %d", st)
	}
	// An invite for an address that already has an account.
	bobTok := h.invite("bob@example.com", future(), false)
	if st, out := h.signup(oidctest.NewBrowser(t), a, url.Values{"name": {"Bob"}, "invite": {bobTok}}); st != http.StatusConflict {
		t.Fatalf("taken email: %d %v", st, out)
	}

	// With the invite: account, passkey, membership, session.
	b := oidctest.NewBrowser(t)
	st, out := h.signup(b, a, url.Values{"name": {"Dana Smith"}, "invite": {tok}})
	if st != http.StatusOK || out["redirect"] != "/app" {
		t.Fatalf("signup: %d %v", st, out)
	}
	var uid, name string
	var verified int
	if err := h.db.QueryRow(`SELECT id, name, email_verified FROM users WHERE email='dana@example.com'`).Scan(&uid, &name, &verified); err != nil {
		t.Fatal(err)
	}
	if name != "Dana Smith" || verified != 1 {
		t.Fatalf("user %q verified %d", name, verified)
	}
	if u, p := h.sessionUser(b); u != uid || p != auth.PasskeyProviderID {
		t.Fatalf("session %q %q", u, p)
	}
	if h.n(`SELECT COUNT(*) FROM memberships WHERE actor_id=? AND org_id='org-acme' AND source='invite'`, uid) != 1 ||
		h.n(`SELECT COUNT(*) FROM invites WHERE email='dana@example.com' AND accepted_at IS NOT NULL`) != 1 {
		t.Fatal("invite not accepted")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.signup' AND actor_id=? AND json_extract(detail_json,'$.method')='invite'`, uid) != 1 {
		t.Fatal("auth.signup not audited")
	}
	// The invite is spent; the passkey signs Dana in.
	if st, _ := h.signup(oidctest.NewBrowser(t), passkeytest.New(), url.Values{"name": {"X"}, "invite": {tok}}); st != http.StatusForbidden {
		t.Fatalf("spent invite: %d", st)
	}
	if st, _ := h.login(oidctest.NewBrowser(t), a, passkeytest.Options{}); st != http.StatusOK {
		t.Fatalf("login after signup: %d", st)
	}
	// /login with the invite offers account creation.
	tok2 := h.invite("erin@example.com", future(), false)
	_, page := h.do(oidctest.NewBrowser(t), http.MethodGet, "/login?invite="+url.QueryEscape(tok2), nil, nil)
	if !strings.Contains(string(page), `data-bc-passkey="signup"`) || !strings.Contains(string(page), "Create account with a passkey") {
		t.Fatal("invite landing has no passkey sign-up")
	}

	// Dana's only method is the passkey: removing it is refused.
	var pk string
	if err := h.db.QueryRow(`SELECT id FROM webauthn_credentials WHERE user_id=?`, uid).Scan(&pk); err != nil {
		t.Fatal(err)
	}
	csrf := h.session(b, uid)
	resp := h.form(b, "/settings/passkeys/"+pk+"/delete", csrf, nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "error=last_method") {
		t.Fatalf("last method delete: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if h.n(`SELECT COUNT(*) FROM webauthn_credentials WHERE id=?`, pk) != 1 {
		t.Fatal("last passkey deleted")
	}
}

func TestPasskeySignupBootstrap(t *testing.T) {
	h := newPKHarness(t, smOpts{unclaimed: true, bootstrapToken: "boot-token-612"})
	a := passkeytest.New()
	q := url.Values{"name": {"Owner"}, "email": {"owner@example.com"}, "bootstrap": {"1"}}
	// Without the setup cookie: refused.
	if st, _ := h.signup(oidctest.NewBrowser(t), a, q); st != http.StatusForbidden {
		t.Fatalf("no setup cookie: %d", st)
	}
	b := oidctest.NewBrowser(t)
	if st, page := h.do(b, http.MethodGet, "/setup?token=boot-token-612", nil, nil); st != http.StatusOK || !strings.Contains(string(page), "Claim with a passkey") {
		t.Fatalf("setup page: %d", st)
	}
	if st, _ := h.signup(b, a, url.Values{"name": {"Owner"}, "email": {"not an email"}, "bootstrap": {"1"}}); st != http.StatusBadRequest {
		t.Fatalf("bad email: %d", st)
	}
	st, out := h.signup(b, a, q)
	if st != http.StatusOK {
		t.Fatalf("bootstrap signup: %d %v", st, out)
	}
	var uid string
	var verified int
	if err := h.db.QueryRow(`SELECT id, email_verified FROM users WHERE email='owner@example.com'`).Scan(&uid, &verified); err != nil {
		t.Fatal(err)
	}
	if verified != 0 {
		t.Fatal("typed bootstrap email marked verified")
	}
	if h.n(`SELECT bootstrap_done FROM platform_settings`) != 1 ||
		h.n(`SELECT COUNT(*) FROM memberships WHERE actor_id=? AND org_id='00000000000000000000000000000000'`, uid) != 1 {
		t.Fatal("platform not claimed")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.bootstrap' AND actor_id=?`, uid) != 1 {
		t.Fatal("auth.bootstrap not audited")
	}
	if b.Cookie(h.base, auth.SetupCookieName) != nil {
		t.Fatal("setup cookie kept")
	}
	// The token is spent.
	b2 := oidctest.NewBrowser(t)
	if st, _ := h.do(b2, http.MethodGet, "/setup?token=boot-token-612", nil, nil); st != http.StatusNotFound {
		t.Fatalf("setup after claim: %d", st)
	}
	// A trusted IdP asserting the typed address never links to the
	// unverified account.
	h.google.SetUser(oidctest.User{Subject: "owner-g", Email: "owner@example.com", EmailVerified: true})
	end := h.follow(oidctest.NewBrowser(t), h.base+"/auth/google")
	if end.Status != http.StatusForbidden || h.n(`SELECT COUNT(*) FROM identities WHERE user_id=?`, uid) != 0 {
		t.Fatalf("IdP linked to an unverified account: %d", end.Status)
	}
}

func TestPasskeyActionsOwnRowsOnly(t *testing.T) {
	h := newPKHarness(t, smOpts{})
	bob, alice := oidctest.NewBrowser(t), oidctest.NewBrowser(t)
	if st, _ := h.add(bob, passkeytest.New(), h.session(bob, "u-bob"), passkeytest.Options{}); st != http.StatusOK {
		t.Fatal("add bob")
	}
	aliceCSRF := h.session(alice, "u-alice")
	if st, _ := h.add(alice, passkeytest.New(), aliceCSRF, passkeytest.Options{}); st != http.StatusOK {
		t.Fatal("add alice")
	}
	var bobPK string
	if err := h.db.QueryRow(`SELECT id FROM webauthn_credentials WHERE user_id='u-bob'`).Scan(&bobPK); err != nil {
		t.Fatal(err)
	}
	resp := h.form(alice, "/settings/passkeys/"+bobPK+"/rename", aliceCSRF, url.Values{"name": {"Mine now"}})
	if !strings.Contains(resp.Header.Get("Location"), "error=passkey_not_found") {
		t.Fatalf("rename other's: %s", resp.Header.Get("Location"))
	}
	resp = h.form(alice, "/settings/passkeys/"+bobPK+"/delete", aliceCSRF, nil)
	if !strings.Contains(resp.Header.Get("Location"), "error=passkey_not_found") {
		t.Fatalf("delete other's: %s", resp.Header.Get("Location"))
	}
	if h.n(`SELECT COUNT(*) FROM webauthn_credentials WHERE id=? AND name='iCloud Keychain'`, bobPK) != 1 {
		t.Fatal("bob's passkey touched")
	}
	// Bob renames and, holding an identity too, removes his own.
	bobCSRF := h.session(bob, "u-bob")
	if resp := h.form(bob, "/settings/passkeys/"+bobPK+"/rename", bobCSRF, url.Values{"name": {"\x01"}}); !strings.Contains(resp.Header.Get("Location"), "error=passkey_name") {
		t.Fatalf("bad name: %s", resp.Header.Get("Location"))
	}
	if resp := h.form(bob, "/settings/passkeys/"+bobPK+"/rename", bobCSRF, url.Values{"name": {"Work laptop"}}); !strings.Contains(resp.Header.Get("Location"), "notice=passkey_renamed") {
		t.Fatalf("rename: %s", resp.Header.Get("Location"))
	}
	// Unlinking Bob's last identity is allowed while he has a passkey.
	if resp := h.form(bob, "/settings/sign-in-methods/unlink/i-bob-g", bobCSRF, nil); !strings.Contains(resp.Header.Get("Location"), "notice=unlinked") {
		t.Fatalf("unlink with passkey: %s", resp.Header.Get("Location"))
	}
	// Now the passkey is his last method.
	if resp := h.form(bob, "/settings/passkeys/"+bobPK+"/delete", bobCSRF, nil); !strings.Contains(resp.Header.Get("Location"), "error=last_method") {
		t.Fatalf("delete last: %s", resp.Header.Get("Location"))
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='passkey.deleted'`) != 0 {
		t.Fatal("refused delete audited")
	}
}

func TestPasskeySessionRefusedByEnforcedSSO(t *testing.T) {
	h := newPKHarness(t, smOpts{})
	a := passkeytest.New()
	bob := oidctest.NewBrowser(t)
	if st, _ := h.add(bob, a, h.session(bob, "u-bob"), passkeytest.Options{}); st != http.StatusOK {
		t.Fatal("add")
	}
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES ('m-bob','org-acme','u-bob','user','org','org-acme','r-member')`)
	h.orgIdP("acme-sso", "org-acme", h.corp, true, false)
	h.exec(`INSERT INTO org_sso_settings (org_id, enforce_sso) VALUES ('org-acme', 1)`)
	b := oidctest.NewBrowser(t)
	if st, _ := h.login(b, a, passkeytest.Options{}); st != http.StatusOK {
		t.Fatal("login")
	}
	st, page := h.do(b, http.MethodGet, "/app/org/org-acme/settings", nil, nil)
	if st != http.StatusForbidden || !strings.Contains(string(page), "This organisation requires single sign-on") {
		t.Fatalf("enforced org via passkey: %d", st)
	}
}

func TestPasskeysDisabled(t *testing.T) {
	h := newPKHarness(t, smOpts{})
	a := passkeytest.New()
	bob := oidctest.NewBrowser(t)
	if st, _ := h.add(bob, a, h.session(bob, "u-bob"), passkeytest.Options{}); st != http.StatusOK {
		t.Fatal("add")
	}
	// Platform admin turns passkeys off on the admin page; Bob cannot.
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES
		('m-pa','00000000000000000000000000000000','u-admin','user','org','00000000000000000000000000000000','00000000000000000000000000000000')`)
	if resp := h.form(bob, "/admin/identity-providers/passkeys", h.session(bob, "u-bob"), url.Values{"passkeys_enabled": {"0"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin toggle: %d", resp.StatusCode)
	}
	admin := oidctest.NewBrowser(t)
	acsrf := h.session(admin, "u-admin")
	if st, page := h.do(admin, http.MethodGet, "/admin/identity-providers", nil, nil); st != http.StatusOK || !strings.Contains(string(page), "Turn passkeys off") {
		t.Fatalf("admin page: %d", st)
	}
	if resp := h.form(admin, "/admin/identity-providers/passkeys", acsrf, url.Values{"passkeys_enabled": {"0"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("toggle off: %d", resp.StatusCode)
	}
	if h.n(`SELECT COUNT(*) FROM platform_settings WHERE json_extract(settings_json,'$.passkeys_enabled')=0`) != 1 {
		t.Fatal("setting not stored")
	}

	// Every endpoint refuses; existing passkeys cannot sign in.
	b := oidctest.NewBrowser(t)
	if st, _ := h.do(b, http.MethodGet, "/auth/passkey/login/begin", nil, nil); st != http.StatusNotFound {
		t.Fatalf("login begin: %d", st)
	}
	opts := []byte(`{"publicKey":{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","rpId":"localhost"}}`)
	body, err := a.Get(opts, h.base, passkeytest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := h.do(b, http.MethodPost, "/auth/passkey/login/finish", body, nil); st != http.StatusNotFound {
		t.Fatalf("login finish: %d", st)
	}
	tok := h.invite("dana@example.com", future(), false)
	if st, _ := h.do(b, http.MethodGet, "/auth/passkey/signup/begin?name=D&invite="+tok, nil, nil); st != http.StatusNotFound {
		t.Fatalf("signup begin: %d", st)
	}
	if st, _ := h.do(b, http.MethodPost, "/auth/passkey/signup/finish", []byte(`{}`), nil); st != http.StatusNotFound {
		t.Fatalf("signup finish: %d", st)
	}
	csrf := h.session(bob, "u-bob")
	if st, _ := h.do(bob, http.MethodPost, "/settings/passkeys/begin", []byte(`{}`), map[string]string{auth.CSRFHeader: csrf}); st != http.StatusNotFound {
		t.Fatalf("add begin: %d", st)
	}
	// The UI hides passkeys.
	if _, page := h.do(b, http.MethodGet, "/login", nil, nil); strings.Contains(string(page), "data-bc-passkey") {
		t.Fatal("login page still offers passkeys")
	}
	if _, page := h.do(bob, http.MethodGet, "/settings/sign-in-methods", nil, nil); strings.Contains(string(page), `data-bc-passkey="add"`) ||
		!strings.Contains(string(page), "Passkeys are turned off") {
		t.Fatal("sign-in methods still offers passkeys")
	}
	// A passkey that can't be used doesn't count as a sign-in method: Bob
	// cannot unlink his only identity.
	if resp := h.form(bob, "/settings/sign-in-methods/unlink/i-bob-g", csrf, nil); !strings.Contains(resp.Header.Get("Location"), "error=last_method") {
		t.Fatalf("unlink with unusable passkey: %s", resp.Header.Get("Location"))
	}
}

func TestPasskeysUnavailableOnIPBaseURL(t *testing.T) {
	h := newSMHarness(t, smOpts{}) // BC_BASE_URL on 127.0.0.1
	resp, err := oidctest.NewBrowser(t).Get(h.app.URL + "/auth/passkey/login/begin")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("begin on an IP base URL: %d", resp.StatusCode)
	}
	end := h.follow(oidctest.NewBrowser(t), "/login")
	if strings.Contains(end.Body, "data-bc-passkey") {
		t.Fatal("login page offers passkeys on an IP base URL")
	}
}
