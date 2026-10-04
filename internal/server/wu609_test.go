package server_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// WU-609: OIDC RP-initiated logout, back-channel logout, the CSRF exemption
// list, and group sync's handling of an absent or overage group claim (Q12),
// end to end through the production wiring against oidctest IdPs. "corp" is
// an env-seeded generic OIDC provider (IdP sign-out on by preset default).

const corpUser = "shared-sub" // u-alice's corp subject (newSMHarness)

// signInCorp signs b in as u-alice through corp with IdP session id sid.
func (h *smHarness) signInCorp(b *oidctest.Browser, sid string) {
	h.t.Helper()
	h.corp.SetUser(oidctest.User{Subject: corpUser, Email: "alice@corp.example", EmailVerified: true, SID: sid})
	if end := h.signIn(b, "corp"); end.Status != http.StatusOK {
		h.t.Fatalf("sign-in via corp: %d %q", end.Status, end.Body)
	}
}

// logout posts the sign-out form with b's CSRF token.
func (h *smHarness) logout(b *oidctest.Browser) *http.Response {
	h.t.Helper()
	return h.postForm(b, "/auth/logout", h.csrfOf(b), nil)
}

// idpSession inserts a live session with IdP provenance.
func (h *smHarness) idpSession(hash, userID, provider, sid, sub string) {
	h.t.Helper()
	h.exec(`INSERT INTO sessions (token_hash, user_id, expires_at, provider_id, auth_method, idp_sid, idp_subject)
		VALUES (?, ?, '2099-01-01T00:00:00.000Z', ?, 'oidc', ?, ?)`, hash, userID, provider, sid, sub)
}

// backChannel posts a logout token as the IdP would: no cookies, no CSRF.
func (h *smHarness) backChannel(provider, token string, cookies ...*http.Cookie) (*http.Response, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.app.URL+"/auth/oidc/"+provider+"/backchannel-logout",
		strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestRPInitiatedLogout(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	b := oidctest.NewBrowser(t)
	h.signInCorp(b, "sid-rp")

	// The session records its IdP provenance (WU-601), including sid and the
	// sealed ID token.
	raw := b.Cookie(h.app.URL, auth.CookieName).Value
	var sid, sub, enc string
	if err := h.db.QueryRow(`SELECT idp_sid, idp_subject, id_token_enc FROM sessions WHERE token_hash=?`, hashOf(raw)).Scan(&sid, &sub, &enc); err != nil {
		t.Fatal(err)
	}
	idToken, err := tenant.Decrypt(tenant.PadKey(testConfig().SecretKey), enc)
	if sid != "sid-rp" || sub != corpUser || err != nil || strings.Count(idToken, ".") != 2 {
		t.Fatalf("session provenance: sid=%q sub=%q token ok=%v", sid, sub, err == nil)
	}

	resp := h.logout(b)
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("logout response is cacheable")
	}
	// The sign-out form cannot 303 to the IdP under CSP form-action
	// 'self'; it answers with a continue page (auth.ContinueTo).
	next := oidctest.NextURL(resp)
	loc, _ := url.Parse(next)
	if resp.StatusCode != http.StatusOK || loc == nil || !strings.HasPrefix(loc.String(), h.corp.Issuer()+"/end_session?") {
		t.Fatalf("logout: %d %q", resp.StatusCode, next)
	}
	q := loc.Query()
	if q.Get("id_token_hint") != idToken || q.Get("client_id") != h.corp.ClientID ||
		q.Get("post_logout_redirect_uri") != h.app.URL+"/login?signed_out=1" || len(q.Get("state")) < 16 {
		t.Errorf("end-session query: %v", q)
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashOf(raw)) != 0 || b.Cookie(h.app.URL, auth.CookieName) != nil {
		t.Error("local session not revoked before the IdP redirect")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.logout' AND actor_id='u-alice' AND detail_json LIKE '%"idp_logout":"1"%'`) != 1 {
		t.Error("IdP logout not audited")
	}
	// The IdP ends its session and returns the browser to the signed-out page.
	end := h.follow(b, loc.String())
	if end.Status != http.StatusOK || !strings.HasPrefix(end.URL, h.app.URL+"/login?signed_out=1") {
		t.Errorf("after end_session: %d %s", end.Status, end.URL)
	}
	if got := h.corp.EndSessionRequests(); len(got) != 1 || got[0].Get("id_token_hint") != idToken {
		t.Errorf("IdP saw %d end_session requests", len(got))
	}
}

func TestRPInitiatedLogoutFallsBackToLocal(t *testing.T) {
	cases := []struct {
		name  string
		setup func(h *smHarness)             // before sign-in
		after func(h *smHarness, raw string) // after sign-in, before logout
	}{
		{name: "end_session unsupported", setup: func(h *smHarness) { h.corp.SetEndSessionSupported(false) }},
		{name: "IdP sign-out turned off", setup: func(h *smHarness) {
			h.exec(`UPDATE auth_providers SET idp_logout=0 WHERE id='corp'`)
			h.srv.IdP().Invalidate()
		}},
		{name: "undecryptable id token", after: func(h *smHarness, raw string) {
			h.exec(`UPDATE sessions SET id_token_enc='not-ciphertext' WHERE token_hash=?`, hashOf(raw))
		}},
		{name: "no id token", after: func(h *smHarness, raw string) {
			h.exec(`UPDATE sessions SET id_token_enc='' WHERE token_hash=?`, hashOf(raw))
		}},
		{name: "provider disabled", after: func(h *smHarness, _ string) {
			h.exec(`UPDATE auth_providers SET enabled=0 WHERE id='corp'`)
			h.srv.IdP().Invalidate()
		}},
		{name: "provider deleted", after: func(h *smHarness, _ string) {
			h.exec(`DELETE FROM identities WHERE provider='corp'`)
			h.exec(`DELETE FROM auth_providers WHERE id='corp'`)
			h.srv.IdP().Invalidate()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSMHarness(t, smOpts{})
			if tc.setup != nil {
				tc.setup(h)
			}
			b := oidctest.NewBrowser(t)
			h.signInCorp(b, "sid-x")
			raw := b.Cookie(h.app.URL, auth.CookieName).Value
			if tc.after != nil {
				tc.after(h, raw)
			}
			resp := h.logout(b)
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != auth.SignedOutURL {
				t.Fatalf("logout: %d %q", resp.StatusCode, resp.Header.Get("Location"))
			}
			if h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashOf(raw)) != 0 {
				t.Error("session not revoked")
			}
			if len(h.corp.EndSessionRequests()) != 0 {
				t.Error("IdP contacted")
			}
		})
	}

	// A Google session (preset without IdP logout) signs out locally too.
	h := newSMHarness(t, smOpts{})
	b := oidctest.NewBrowser(t)
	h.google.SetUser(oidctest.User{Subject: "bob-g", Email: "bob@example.com", EmailVerified: true})
	if end := h.signIn(b, "google"); end.Status != http.StatusOK {
		t.Fatal(end.Status)
	}
	if resp := h.logout(b); resp.Header.Get("Location") != auth.SignedOutURL {
		t.Errorf("google logout: %q", resp.Header.Get("Location"))
	}
}

func TestBackChannelLogout(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	// corp sessions: two IdP sessions for alice's subject, one for another
	// subject; google sessions reuse the same sid and sub values and must
	// never be touched by corp's tokens.
	reset := func() {
		h.exec(`DELETE FROM sessions`)
		h.idpSession("c-a1", "u-alice", "corp", "sid-a", corpUser)
		h.idpSession("c-a2", "u-alice", "corp", "sid-b", corpUser)
		h.idpSession("c-o", "u-bob", "corp", "sid-o", "other-sub")
		h.idpSession("g-a", "u-bob", "google", "sid-a", corpUser)
		h.idpSession("g-b", "u-bob", "google", "sid-b", corpUser)
	}
	live := func() string {
		rows, err := h.db.Query(`SELECT token_hash FROM sessions ORDER BY token_hash`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			out = append(out, s)
		}
		return strings.Join(out, ",")
	}
	all := "c-a1,c-a2,c-o,g-a,g-b"
	token := func(o oidctest.LogoutTokenOptions) string {
		t.Helper()
		tok, err := h.corp.LogoutToken(o)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	expect := func(name string, tok string, status int, want string) {
		t.Helper()
		resp, body := h.backChannel("corp", tok)
		if resp.StatusCode != status || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: status %d cache %q", name, resp.StatusCode, resp.Header.Get("Cache-Control"))
		}
		if strings.Contains(body, "oidc") || strings.Contains(body, "nonce") || strings.Contains(body, "aud") {
			t.Errorf("%s: response leaks detail: %q", name, body)
		}
		if got := live(); got != want {
			t.Errorf("%s: sessions %s, want %s", name, got, want)
		}
	}

	reset()
	expect("by sid", token(oidctest.LogoutTokenOptions{SID: "sid-a"}), http.StatusOK, "c-a2,c-o,g-a,g-b")
	var detail string
	if err := h.db.QueryRow(`SELECT detail_json FROM audit_log WHERE action='auth.backchannel_logout' AND subject='corp' AND org_id IS NULL`).Scan(&detail); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !strings.Contains(detail, `"revoked":"1"`) || !strings.Contains(detail, `"matched":"sid"`) {
		t.Errorf("audit detail %s", detail)
	}
	reset()
	expect("by sub", token(oidctest.LogoutTokenOptions{Subject: corpUser}), http.StatusOK, "c-o,g-a,g-b")
	reset()
	expect("sid and sub", token(oidctest.LogoutTokenOptions{SID: "sid-b", Subject: corpUser}), http.StatusOK, "c-a1,c-o,g-a,g-b")
	reset()
	expect("sid with another sub", token(oidctest.LogoutTokenOptions{SID: "sid-a", Subject: "other-sub"}), http.StatusOK, all)
	expect("nothing matches", token(oidctest.LogoutTokenOptions{SID: "sid-unknown"}), http.StatusOK, all)
	expect("no typ, no exp", token(oidctest.LogoutTokenOptions{SID: "sid-o", Typ: "-", OmitExp: true}), http.StatusOK, "c-a1,c-a2,g-a,g-b")
	reset()
	expect("typ JWT", token(oidctest.LogoutTokenOptions{SID: "sid-o", Typ: "JWT"}), http.StatusOK, "c-a1,c-a2,g-a,g-b")

	// Every malformed or misdirected token: 400, nothing revoked.
	reset()
	stale := time.Now().Add(-10 * time.Minute)
	bad := map[string]oidctest.LogoutTokenOptions{
		"nonce":          {SID: "sid-a", Nonce: "n-1"},
		"wrong aud":      {SID: "sid-a", WrongAudience: true},
		"wrong iss":      {SID: "sid-a", WrongIssuer: true},
		"missing events": {SID: "sid-a", OmitEvents: true},
		"events array":   {SID: "sid-a", EventsArray: true},
		"other event":    {SID: "sid-a", Claims: map[string]any{"events": map[string]any{"http://example.com/other": map[string]any{}}}},
		"stale iat":      {SID: "sid-a", IssuedAt: stale, OmitExp: true},
		"future iat":     {SID: "sid-a", IssuedAt: time.Now().Add(10 * time.Minute)},
		"missing iat":    {SID: "sid-a", Claims: map[string]any{"iat": nil}},
		"expired":        {SID: "sid-a", Expired: true},
		"bad signature":  {SID: "sid-a", WrongKey: true},
		"alg none":       {SID: "sid-a", AlgNone: true},
		"missing jti":    {SID: "sid-a", OmitJTI: true},
		"no sid or sub":  {},
		"access token":   {SID: "sid-a", Typ: "at+jwt"},
	}
	for name, o := range bad {
		expect(name, token(o), http.StatusBadRequest, all)
	}
	expect("garbage", "not.a.jwt", http.StatusBadRequest, all)
	expect("empty", "", http.StatusBadRequest, all)
	if resp, _ := h.backChannel("nope", token(oidctest.LogoutTokenOptions{SID: "sid-a"})); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown provider: %d", resp.StatusCode)
	}
	// A valid corp token sent to google's endpoint fails google's checks.
	if resp, _ := h.backChannel("google", token(oidctest.LogoutTokenOptions{SID: "sid-a"})); resp.StatusCode != http.StatusBadRequest || live() != all {
		t.Errorf("corp token at google: %d", resp.StatusCode)
	}

	// Replay: the same jti is accepted once.
	tok := token(oidctest.LogoutTokenOptions{SID: "sid-a", JTI: "jti-once"})
	expect("first use", tok, http.StatusOK, "c-a2,c-o,g-a,g-b")
	reset()
	expect("replayed", tok, http.StatusBadRequest, all)
	expect("replayed jti, new token", token(oidctest.LogoutTokenOptions{SID: "sid-b", JTI: "jti-once"}), http.StatusBadRequest, all)

	// An org-owned provider's back-channel logout is in the org's audit log.
	acme := oidctest.New(t)
	h.orgIdP("acme-sso", "org-acme", acme, true, false)
	h.idpSession("o-1", "u-alice", "acme-sso", "sid-org", "org-sub")
	otok, _ := acme.LogoutToken(oidctest.LogoutTokenOptions{Subject: "org-sub"})
	if resp, _ := h.backChannel("acme-sso", otok); resp.StatusCode != http.StatusOK || h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash='o-1'`) != 0 {
		t.Fatalf("org provider back-channel: %d", resp.StatusCode)
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.backchannel_logout' AND org_id='org-acme' AND actor_type='service' AND actor_id='idp:acme-sso'`) != 1 {
		t.Error("org back-channel logout not in the org audit log")
	}
}

// The back-channel endpoint is CSRF-exempt and never sees the session: a
// browser cookie on the request is neither required nor resolved (its
// sliding expiry is not touched and no cookie is set).
func TestBackChannelLogoutIgnoresSessionCookie(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	b := oidctest.NewBrowser(t)
	raw, _ := h.signedIn(b, "u-alice")
	h.exec(`UPDATE sessions SET last_seen_at='2020-01-01T00:00:00.000Z' WHERE token_hash=?`, hashOf(raw))
	h.idpSession("c-a1", "u-alice", "corp", "sid-a", corpUser)
	tok, err := h.corp.LogoutToken(oidctest.LogoutTokenOptions{SID: "sid-a"})
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := h.backChannel("corp", tok, &http.Cookie{Name: auth.CookieName, Value: raw})
	if resp.StatusCode != http.StatusOK || h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash='c-a1'`) != 0 {
		t.Fatalf("with a session cookie and no CSRF token: %d", resp.StatusCode)
	}
	if len(resp.Cookies()) != 0 {
		t.Errorf("response set cookies: %v", resp.Cookies())
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash=? AND last_seen_at='2020-01-01T00:00:00.000Z'`, hashOf(raw)) != 1 {
		t.Error("the session middleware resolved the cookie on an exempt route")
	}
	// Other POSTs still need the CSRF token.
	if r := h.postForm(b, "/auth/logout", "", nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("logout without CSRF: %d", r.StatusCode)
	}
}

func TestBackChannelLogoutRateLimited(t *testing.T) {
	h := newSMHarness(t, smOpts{defaultRateLimit: true})
	limited := false
	for i := 0; i < 15 && !limited; i++ {
		resp, _ := h.backChannel("corp", "x")
		limited = resp.StatusCode == http.StatusTooManyRequests
	}
	if !limited {
		t.Error("back-channel logout is not rate-limited")
	}
}

// Q12 (amended in WU-609): an absent group claim or an Entra groups overage
// skips reconciliation; a present, empty claim still removes idp
// memberships.
func TestGroupSyncAbsentClaimAndOverage(t *testing.T) {
	h, acme, _, d := wu608Setup(t, smOpts{})
	alice := user("u-alice", "")
	if _, err := call(d, alice, "org-acme", action.ActionIdPMappingCreate, map[string]string{"group_value": "eng", "role_id": "r-member"}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(d, alice, "org-acme", "org.sso.update", map[string]any{"group_sync": true}); err != nil {
		t.Fatal(err)
	}
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-helen','helen@corp.example','Helen')`)
	h.exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES ('i-helen-a','u-helen','acme-sso','s-helen','helen@corp.example')`)
	signIn := func(extra map[string]any, groups ...string) {
		t.Helper()
		acme.SetUser(oidctest.User{Subject: "s-helen", Email: "helen@corp.example", EmailVerified: true, Groups: groups, Extra: extra})
		if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusOK {
			t.Fatalf("sign-in: %d %q", end.Status, end.Body)
		}
	}
	org := func() string { return h.membership("org-acme", "u-helen", "org", "org-acme") }
	audits := func(act string) int {
		return h.n(`SELECT COUNT(*) FROM audit_log WHERE action=? AND org_id='org-acme' AND subject='u-helen'`, act)
	}

	signIn(nil, "eng")
	if org() != "r-member/idp" || audits("membership.synced") != 1 {
		t.Fatalf("initial sync: %q", org())
	}
	// Absent claim: nothing reconciled, nothing audited.
	signIn(nil)
	if org() != "r-member/idp" || audits("membership.synced") != 1 || audits("membership.sync_skipped") != 0 {
		t.Fatalf("absent claim: %q", org())
	}
	// Entra overage, both shapes: skipped with an audit note.
	signIn(map[string]any{"_claim_names": map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://graph.microsoft.com/v1.0/users/x/getMemberObjects"}}})
	signIn(map[string]any{"hasgroups": true})
	if org() != "r-member/idp" || audits("membership.sync_skipped") != 2 {
		t.Fatalf("overage: %q, %d skip audits", org(), audits("membership.sync_skipped"))
	}
	var detail string
	if err := h.db.QueryRow(`SELECT detail_json FROM audit_log WHERE action='membership.sync_skipped' LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, `"reason":"groups_overage"`) || !strings.Contains(detail, `"provider":"acme-sso"`) {
		t.Errorf("skip audit detail: %s", detail)
	}
	// The org's group_claim override: absent there skips too, even when the
	// provider's own groups claim is present.
	if _, err := call(d, alice, "org-acme", "org.sso.update", map[string]any{"group_claim": "app.roles"}); err != nil {
		t.Fatal(err)
	}
	signIn(nil)
	if org() != "r-member/idp" {
		t.Fatalf("absent override claim: %q", org())
	}
	signIn(map[string]any{"app": map[string]any{"roles": []string{}}}, "eng")
	if org() != "" {
		t.Fatalf("present, empty override claim: %q", org())
	}
	if _, err := call(d, alice, "org-acme", "org.sso.update", map[string]any{"group_claim": ""}); err != nil {
		t.Fatal(err)
	}
	// Present and empty removes the idp membership.
	signIn(nil, "eng")
	signIn(noGroups)
	if org() != "" {
		t.Fatalf("present, empty claim: %q", org())
	}
}
