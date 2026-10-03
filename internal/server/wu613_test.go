package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/event"
	"github.com/thomasteoh/boardchestrator/internal/job"
	"github.com/thomasteoh/boardchestrator/internal/webhook"
)

// WU-613: session and API-key lifecycle, last-owner protection and the SSO
// gaps on /events and /app/chat, through the production wiring.

// sessionVia gives b a fresh session for userID signed in through provider.
func (h *smHarness) sessionVia(b *oidctest.Browser, userID, provider string) (raw, csrf string) {
	h.t.Helper()
	raw, csrf = h.signedIn(b, userID)
	h.exec(`UPDATE sessions SET provider_id=?, auth_method='oidc' WHERE token_hash=?`, provider, hashOf(raw))
	return raw, csrf
}

// hx posts form as htmx does (CSRF in the header) and returns the response
// and body.
func (h *smHarness) hx(b *oidctest.Browser, path, csrf string, form url.Values) (*http.Response, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.app.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	if csrf != "" {
		req.Header.Set(auth.CSRFHeader, csrf)
	}
	resp, err := b.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// sessionCleared reports whether resp expires the session cookie.
func sessionCleared(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestSessionsPageListAndRevoke(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	b := oidctest.NewBrowser(t)
	cur, csrf := h.sessionVia(b, "u-bob", "google")
	other, _ := h.sessionVia(oidctest.NewBrowser(t), "u-bob", "corp")
	third, _ := h.signedIn(oidctest.NewBrowser(t), "u-bob")
	alice, _ := h.signedIn(oidctest.NewBrowser(t), "u-alice")
	h.exec(`UPDATE sessions SET ua='Firefox on Linux', ip='192.0.2.9' WHERE token_hash=?`, hashOf(other))

	status, _, page := h.get(b, "/api/sessions")
	if status != http.StatusOK {
		t.Fatalf("sessions: %d", status)
	}
	for _, raw := range []string{cur, other, third, alice} {
		if strings.Contains(page, raw) || strings.Contains(page, hashOf(raw)) {
			t.Fatal("sessions page shows a token or a token hash")
		}
	}
	if strings.Contains(page, action.SessionPublicID(hashOf(alice))) {
		t.Fatal("sessions page lists another user's session")
	}
	for _, want := range []string{action.SessionPublicID(hashOf(cur)), action.SessionPublicID(hashOf(other)),
		"This device", "Firefox on Linux", "192.0.2.9", "Corp", "OpenID Connect", "Sign out everywhere else"} {
		if !strings.Contains(page, want) {
			t.Errorf("sessions page lacks %q", want)
		}
	}
	if strings.Count(page, "This device") != 1 {
		t.Error("current session not marked exactly once")
	}

	// The revoke button: an opaque id, CSRF header, scoped to the caller.
	if resp, _ := h.hx(b, "/api/action/session.revoke", csrf, url.Values{"id": {action.SessionPublicID(hashOf(alice))}}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("revoke another user's session: %d", resp.StatusCode)
	}
	if resp, _ := h.hx(b, "/api/action/session.revoke", "", url.Values{"id": {action.SessionPublicID(hashOf(other))}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("revoke without CSRF: %d", resp.StatusCode)
	}
	resp, _ := h.hx(b, "/api/action/session.revoke", csrf, url.Values{"id": {action.SessionPublicID(hashOf(other))}})
	if resp.StatusCode != http.StatusOK || sessionCleared(resp) {
		t.Fatalf("revoke other: %d", resp.StatusCode)
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashOf(other)) != 0 ||
		h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashOf(alice)) != 1 {
		t.Fatal("revoke removed the wrong sessions")
	}

	// Everywhere else keeps this one.
	resp, body := h.hx(b, "/api/action/session.revoke_all", csrf, url.Values{"keep_current": {"1"}})
	if resp.StatusCode != http.StatusOK || sessionCleared(resp) || !strings.Contains(body, "This device") {
		t.Fatalf("everywhere else: %d %q", resp.StatusCode, body)
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-bob'`) != 1 || h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashOf(cur)) != 1 {
		t.Fatal("everywhere else left the wrong sessions")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='session.revoke_all' AND actor_id='u-bob'`) != 1 {
		t.Error("session.revoke_all not audited")
	}

	// Revoking the current session signs this browser out.
	resp, _ = h.hx(b, "/api/action/session.revoke", csrf, url.Values{"id": {action.SessionPublicID(hashOf(cur))}})
	if resp.StatusCode != http.StatusOK || !sessionCleared(resp) || resp.Header.Get("HX-Redirect") != "/login?signed_out=1" {
		t.Fatalf("revoke current: %d %v", resp.StatusCode, resp.Header)
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-bob'`) != 0 {
		t.Fatal("current session survived")
	}
}

func TestSessionsSignOutEverywhere(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	b := oidctest.NewBrowser(t)
	_, csrf := h.signedIn(b, "u-bob")
	h.signedIn(oidctest.NewBrowser(t), "u-bob")
	h.signedIn(oidctest.NewBrowser(t), "u-alice")
	resp, _ := h.hx(b, "/api/action/session.revoke_all", csrf, url.Values{"keep_current": {"0"}})
	if resp.StatusCode != http.StatusOK || !sessionCleared(resp) || resp.Header.Get("HX-Redirect") != "/login?signed_out=1" {
		t.Fatalf("everywhere: %d %v", resp.StatusCode, resp.Header)
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-bob'`) != 0 || h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-alice'`) != 1 {
		t.Fatal("sign out everywhere touched the wrong sessions")
	}
	// The browser is now signed out.
	if status, _, _ := h.get(b, "/api/sessions"); status != http.StatusUnauthorized {
		t.Errorf("after sign out: %d", status)
	}
}

func TestPlatformAdminRevokesUserSessions(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	if err := grantPlatformOwner(h, "u-admin"); err != nil {
		t.Fatal(err)
	}
	d, _ := orgDispatcher(h)
	h.signedIn(oidctest.NewBrowser(t), "u-bob")
	h.signedIn(oidctest.NewBrowser(t), "u-bob")
	h.signedIn(oidctest.NewBrowser(t), "u-alice")
	// An org owner (alice holds "*" in org-acme) cannot, with or without an org.
	if _, err := call(d, user("u-alice", ""), "", action.ActionUserSessionsRevoke, map[string]string{"user_id": "u-bob"}); !refused(err) {
		t.Fatalf("org owner: %v", err)
	}
	if _, err := call(d, user("u-alice", ""), "org-acme", action.ActionUserSessionsRevoke, map[string]string{"user_id": "u-bob"}); !refused(err) {
		t.Fatalf("org owner with org: %v", err)
	}
	out, err := call(d, user("u-admin", ""), "", action.ActionUserSessionsRevoke, map[string]string{"user_id": "u-bob"})
	if err != nil {
		t.Fatal(err)
	}
	if out.(map[string]any)["revoked"] != int64(2) {
		t.Errorf("result %v", out)
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-bob'`) != 0 || h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-alice'`) != 1 {
		t.Fatal("wrong sessions revoked")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='user.sessions.revoke' AND actor_id='u-admin' AND subject='u-bob'`) != 1 {
		t.Error("not audited")
	}
	if _, err := call(d, user("u-admin", ""), "", action.ActionUserSessionsRevoke, map[string]string{"user_id": "nobody"}); err == nil {
		t.Error("unknown user accepted")
	}
}

func TestUserDeletionRevokesSessions(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	if err := grantPlatformOwner(h, "u-admin"); err != nil {
		t.Fatal(err)
	}
	d, _ := orgDispatcher(h)
	h.signedIn(oidctest.NewBrowser(t), "u-bob")
	if _, err := call(d, user("u-admin", ""), "", "user.delete", map[string]string{"user_id": "u-bob"}); err != nil {
		t.Fatal(err)
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-bob'`) != 0 {
		t.Fatal("user.delete left sessions")
	}
}

func TestUnlinkRevokesItsSessions(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	h.exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES ('i-bob-c','u-bob','corp','bob-c','bob@corp.example')`)
	b := oidctest.NewBrowser(t)
	cur, csrf := h.sessionVia(b, "u-bob", "google")
	viaCorp, _ := h.sessionVia(oidctest.NewBrowser(t), "u-bob", "corp")
	aliceCorp, _ := h.sessionVia(oidctest.NewBrowser(t), "u-alice", "corp")

	resp := h.post(b, "/settings/sign-in-methods/unlink/i-bob-c", csrf)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "notice=unlinked") || sessionCleared(resp) {
		t.Fatalf("unlink: %d %s", resp.StatusCode, loc)
	}
	for raw, want := range map[string]int{cur: 1, viaCorp: 0, aliceCorp: 1} {
		if got := h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashOf(raw)); got != want {
			t.Errorf("session (want %d) has %d rows", want, got)
		}
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='identity.unlinked' AND detail_json LIKE '%"sessions_revoked":1%'`) != 1 {
		t.Error("revoked sessions not in the audit row")
	}

	// Unlinking the identity this session signed in through signs out.
	h.exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES ('i-bob-c2','u-bob','corp','bob-c2','bob@corp.example')`)
	b2 := oidctest.NewBrowser(t)
	_, csrf2 := h.sessionVia(b2, "u-bob", "corp")
	resp = h.post(b2, "/settings/sign-in-methods/unlink/i-bob-c2", csrf2)
	if loc := resp.Header.Get("Location"); loc != "/login?signed_out=1" || !sessionCleared(resp) {
		t.Fatalf("unlink current: %d %s", resp.StatusCode, loc)
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-bob' AND provider_id='corp'`) != 0 {
		t.Fatal("corp sessions survived")
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashOf(cur)) != 1 {
		t.Fatal("the google session went too")
	}
}

// createKey dispatches apikey.create and returns the result.
func createKey(t *testing.T, d *action.Dispatcher, actor action.Actor, org string, in map[string]any, idem string) action.APIKeyCreated {
	t.Helper()
	raw, _ := json.Marshal(in)
	out, err := d.Dispatch(context.Background(), actor, "apikey.create", raw, action.Opts{Org: org, Idem: idem})
	if err != nil {
		t.Fatal(err)
	}
	return out.(action.APIKeyCreated)
}

func TestAPIKeyCreateSecretNeverStored(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	d, rec := orgDispatcher(h)
	h.exec(`INSERT INTO webhooks (id, org_id, name, url, event_filter) VALUES ('wh1','org-acme','All','https://hooks.example/x','[]')`)
	alice := user("u-alice", "")

	k := createKey(t, d, alice, "org-acme", map[string]any{"name": "CI", "scope": []string{"task.*"}}, "idem-key-1")
	if len(k.Secret) != 72 || k.Secret[:8] != k.Prefix || k.ExpiresAt == "" {
		t.Fatalf("created %+v", k)
	}
	// Default expiry is 90 days.
	exp, err := time.Parse("2006-01-02T15:04:05.000Z", k.ExpiresAt)
	if err != nil || exp.Sub(time.Now()) < 89*24*time.Hour || exp.Sub(time.Now()) > 91*24*time.Hour {
		t.Errorf("expires %s", k.ExpiresAt)
	}
	secret := k.Secret[8:]
	if h.n(`SELECT COUNT(*) FROM idempotency_keys WHERE key='idem-key-1'`) != 1 || h.n(`SELECT COUNT(*) FROM audit_log WHERE action='apikey.create'`) != 1 {
		t.Fatal("no idempotency or audit row (the checks below would be vacuous)")
	}
	for _, q := range []string{
		`SELECT COUNT(*) FROM audit_log WHERE detail_json LIKE '%'||?||'%'`,
		`SELECT COUNT(*) FROM idempotency_keys WHERE result_json LIKE '%'||?||'%'`,
		`SELECT COUNT(*) FROM api_keys WHERE hash LIKE '%'||?||'%'`,
	} {
		if h.n(q, secret) != 0 {
			t.Errorf("secret stored: %s", q)
		}
	}
	// Events (SSE and webhooks take the event payload).
	wh := webhook.New(h.db, job.NewJobStore(h.db))
	seen := false
	for _, ev := range rec.all() {
		if ev.Name != "apikey.create" {
			continue
		}
		seen = true
		if strings.Contains(string(ev.Payload), secret) || !strings.Contains(string(ev.Payload), k.ID) {
			t.Errorf("event payload %s", ev.Payload)
		}
		if err := wh.HandleEvent(context.Background(), event.Event{Name: ev.Name, Org: ev.Org, ActorType: string(ev.Actor.Type),
			ActorID: ev.Actor.ID, Subject: ev.Subject, Payload: ev.Payload}); err != nil {
			t.Fatal(err)
		}
	}
	if !seen {
		t.Fatal("no apikey.create event")
	}
	if h.n(`SELECT COUNT(*) FROM webhook_deliveries`) != 1 || h.n(`SELECT COUNT(*) FROM webhook_deliveries WHERE event_json LIKE '%'||?||'%'`, secret) != 0 {
		t.Error("webhook delivery carries the secret (or none queued)")
	}
	// An idempotent replay returns the redacted form, never the secret.
	raw, _ := json.Marshal(map[string]any{"name": "CI"})
	out, err := d.Dispatch(context.Background(), alice, "apikey.create", raw, action.Opts{Org: "org-acme", Idem: "idem-key-1"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), secret) {
		t.Error("replay returned the secret")
	}

	// Expiry choices.
	for i, c := range []struct {
		in   any
		want bool
	}{{0, false}, {"0", false}, {30, true}, {"365", true}, {"", true}} {
		k := createKey(t, d, alice, "org-acme", map[string]any{"name": fmt.Sprintf("k-%d", i), "expires_in_days": c.in}, "")
		if (k.ExpiresAt != "") != c.want {
			t.Errorf("expires_in_days %v -> %q", c.in, k.ExpiresAt)
		}
	}
	for _, in := range []any{-1, 3651, "soon"} {
		raw, _ := json.Marshal(map[string]any{"name": "bad", "expires_in_days": in})
		if _, err := d.Dispatch(context.Background(), alice, "apikey.create", raw, action.Opts{Org: "org-acme"}); !errors.Is(err, action.ErrAPIKeyExpiry) {
			t.Errorf("expires_in_days %v: %v", in, err)
		}
	}
	// Agents cannot mint keys (the secret would land in their run log).
	raw, _ = json.Marshal(map[string]any{"name": "agent"})
	if _, err := d.Dispatch(context.Background(), action.Actor{Type: action.ActorAgent, ID: "agent-x"}, "apikey.create", raw, action.Opts{Org: "org-acme"}); err == nil {
		t.Error("agent minted a key")
	}
}

func TestAPIKeyExpiryEnforcedREST(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	d, _ := orgDispatcher(h)
	k := createKey(t, d, user("u-alice", ""), "org-acme", map[string]any{"name": "rest", "expires_in_days": 30}, "")
	get := func() int {
		req, _ := http.NewRequest(http.MethodGet, h.app.URL+"/api/v1/orgs/org-acme/projects", nil)
		req.Header.Set("Authorization", "Bearer "+k.Secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if s := get(); s != http.StatusOK {
		t.Fatalf("live key: %d", s)
	}
	h.exec(`UPDATE api_keys SET expires_at='2000-01-01T00:00:00.000Z' WHERE id=?`, k.ID)
	if s := get(); s != http.StatusUnauthorized {
		t.Fatalf("expired key: %d", s)
	}
	// A wrong secret with the right prefix is refused too.
	h.exec(`UPDATE api_keys SET expires_at=NULL WHERE id=?`, k.ID)
	k.Secret = k.Prefix + strings.Repeat("0", 64)
	if s := get(); s != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", s)
	}
}

func TestOrgOwnerListsAndRevokesOrgKeys(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	d, _ := orgDispatcher(h)
	alice, bob, admin := user("u-alice", ""), user("u-bob", ""), user("u-admin", "")
	mine := createKey(t, d, alice, "org-acme", map[string]any{"name": "alice-ci"}, "")
	theirs := createKey(t, d, admin, "org-b", map[string]any{"name": "beta-ci"}, "")
	// bob cannot create keys (Member), so his key is seeded directly.
	h.exec(`INSERT INTO api_keys (id, user_id, org_id, name, prefix, hash, expires_at) VALUES ('k-bob','u-bob','org-acme','bob-laptop','b0b0b0b0','x','2999-01-01T00:00:00.000Z')`)

	out, err := call(d, alice, "org-acme", action.ActionAPIKeyOrgList, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	keys := out.([]action.APIKeyView)
	b, _ := json.Marshal(keys)
	if len(keys) != 2 || strings.Contains(string(b), mine.Secret[8:]) || strings.Contains(string(b), `"hash"`) ||
		!strings.Contains(string(b), "Bob") || strings.Contains(string(b), theirs.ID) {
		t.Fatalf("org list: %s", b)
	}
	// Not an owner, or not a member of the org: refused.
	if _, err := call(d, bob, "org-acme", action.ActionAPIKeyOrgList, struct{}{}); !refused(err) {
		t.Errorf("member listed org keys: %v", err)
	}
	if _, err := call(d, alice, "org-b", action.ActionAPIKeyOrgList, struct{}{}); !refused(err) {
		t.Errorf("listed another org's keys: %v", err)
	}
	if _, err := call(d, alice, "org-b", action.ActionAPIKeyOrgRevoke, map[string]string{"id": theirs.ID}); !refused(err) {
		t.Errorf("revoked in another org: %v", err)
	}
	// Naming another org's key from your own org: not found, untouched.
	if _, err := call(d, alice, "org-acme", action.ActionAPIKeyOrgRevoke, map[string]string{"id": theirs.ID}); !errors.Is(err, action.ErrAPIKeyNotFound) {
		t.Errorf("cross-org revoke: %v", err)
	}
	if h.n(`SELECT COUNT(*) FROM api_keys WHERE id=? AND revoked_at IS NULL`, theirs.ID) != 1 {
		t.Fatal("another org's key was revoked")
	}
	// Owner revokes bob's key.
	if _, err := call(d, alice, "org-acme", action.ActionAPIKeyOrgRevoke, map[string]string{"id": "k-bob"}); err != nil {
		t.Fatal(err)
	}
	if h.n(`SELECT COUNT(*) FROM api_keys WHERE id='k-bob' AND revoked_at IS NOT NULL`) != 1 {
		t.Fatal("bob's key not revoked")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='apikey.org_revoke' AND org_id='org-acme' AND actor_id='u-alice'`) != 1 {
		t.Error("org revoke not audited")
	}
	// apikey.revoke only reaches your own keys; apikey.list shows only yours, no hash.
	if _, err := call(d, admin, "org-b", "apikey.revoke", map[string]string{"id": mine.ID}); !errors.Is(err, action.ErrAPIKeyNotFound) {
		t.Errorf("revoke someone else's key: %v", err)
	}
	out, err = call(d, alice, "org-acme", "apikey.list", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(out)
	if own := out.([]action.APIKeyView); len(own) != 1 || own[0].ID != mine.ID || strings.Contains(string(b), `"hash"`) {
		t.Fatalf("own list: %s", b)
	}
}

func TestAPIKeyPages(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	h.exec(`INSERT INTO api_keys (id, user_id, org_id, name, prefix, hash) VALUES ('k-bob','u-bob','org-acme','bob-laptop','b0b0b0b0','x')`)
	b := oidctest.NewBrowser(t)
	_, csrf := h.signedIn(b, "u-alice")

	resp := h.postForm(b, "/app/org/org-acme/apikeys", csrf, url.Values{"name": {"deploy"}, "scope": {"task.*, project.read"}, "expires_in_days": {"30"}})
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %v", resp.StatusCode, resp.Header)
	}
	var id, prefix string
	if err := h.db.QueryRow(`SELECT id, prefix FROM api_keys WHERE name='deploy' AND user_id='u-alice' AND org_id='org-acme' AND expires_at IS NOT NULL`).Scan(&id, &prefix); err != nil {
		t.Fatal(err)
	}
	// The create response showed the key once; the page never does again.
	req, _ := http.NewRequest(http.MethodPost, h.app.URL+"/app/org/org-acme/apikeys", strings.NewReader(url.Values{"csrf_token": {csrf}, "name": {"second"}, "expires_in_days": {"0"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cr, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	created, _ := io.ReadAll(cr.Body)
	_ = cr.Body.Close()
	var p2 string
	if err := h.db.QueryRow(`SELECT prefix FROM api_keys WHERE name='second' AND expires_at IS NULL`).Scan(&p2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(created), `id="apikey-new">`+p2) {
		t.Fatalf("create page does not show the new key: %s", created)
	}
	_, _, page := h.get(b, "/app/org/org-acme/apikeys")
	if strings.Contains(page, "apikey-new") || !strings.Contains(page, "deploy") || !strings.Contains(page, "All API keys in this organisation") {
		t.Errorf("keys page: %s", page)
	}
	if !strings.Contains(page, `["task.*","project.read"]`) && !strings.Contains(page, `[&#34;task.*&#34;,&#34;project.read&#34;]`) {
		t.Errorf("scope from the form not stored: %s", page)
	}
	// Bad expiry from a forged form: refused with fixed copy.
	resp = h.postForm(b, "/app/org/org-acme/apikeys", csrf, url.Values{"name": {"x"}, "expires_in_days": {"9999"}})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "?error=expiry") {
		t.Errorf("bad expiry: %d %s", resp.StatusCode, loc)
	}
	// Revoke your own.
	resp = h.postForm(b, "/app/org/org-acme/apikeys/"+id+"/revoke", csrf, nil)
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "?notice=revoked") || h.n(`SELECT COUNT(*) FROM api_keys WHERE id=? AND revoked_at IS NOT NULL`, id) != 1 {
		t.Fatalf("revoke: %s", loc)
	}

	// Org page: owner sees bob's key (no secret material) and revokes it.
	status, _, org := h.get(b, "/app/org/org-acme/settings/api-keys")
	if status != http.StatusOK || !strings.Contains(org, "bob-laptop") || !strings.Contains(org, "bob@example.com") || strings.Contains(org, `"x"`) {
		t.Fatalf("org keys page: %d %s", status, org)
	}
	resp = h.postForm(b, "/app/org/org-acme/settings/api-keys/k-bob/revoke", csrf, nil)
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "/settings/api-keys?notice=revoked") || h.n(`SELECT COUNT(*) FROM api_keys WHERE id='k-bob' AND revoked_at IS NOT NULL`) != 1 {
		t.Fatalf("org revoke: %s", loc)
	}
	// A member gets 403 on the org page.
	bb := oidctest.NewBrowser(t)
	h.signedIn(bb, "u-bob")
	if status, _, _ := h.get(bb, "/app/org/org-acme/settings/api-keys"); status != http.StatusForbidden {
		t.Errorf("member on org keys page: %d", status)
	}
	// Org settings links to it.
	_, _, settings := h.get(b, "/app/org/org-acme/settings")
	if !strings.Contains(settings, "/app/org/org-acme/settings/api-keys") {
		t.Error("org settings has no API keys link")
	}
}

func TestLastOwnerManualPaths(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	d, _ := orgDispatcher(h)
	alice := user("u-alice", "")
	// m-alice is org-acme's only owner.
	if _, err := call(d, alice, "org-acme", "membership.delete", map[string]string{"id": "m-alice", "org_id": "org-acme"}); !errors.Is(err, action.ErrLastOwner) {
		t.Errorf("membership.delete: %v", err)
	}
	if _, err := call(d, alice, "org-acme", "member.remove", map[string]string{"org_id": "org-acme", "actor_id": "u-alice", "actor_type": "user", "resource_type": "org", "resource_id": "org-acme"}); !errors.Is(err, action.ErrLastOwner) {
		t.Errorf("member.remove: %v", err)
	}
	if _, err := call(d, alice, "org-acme", "role.update", map[string]any{"id": "r-owner", "org_id": "org-acme", "name": "Owner", "grants": []string{"task.*"}}); !errors.Is(err, action.ErrLastOwner) {
		t.Errorf("role.update dropping *: %v", err)
	}
	if h.membership("org-acme", "u-alice", "org", "org-acme") != "r-owner/manual" || h.str(`SELECT grants_json FROM roles WHERE id='r-owner'`) != `["*"]` {
		t.Fatal("a refused change was applied")
	}
	// Removing a non-owner, and editing a role nobody owns through, are fine.
	if _, err := call(d, alice, "org-acme", "membership.delete", map[string]string{"id": "m-bob", "org_id": "org-acme"}); err != nil {
		t.Errorf("remove member: %v", err)
	}
	// With a second owner the first can go.
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES ('m-bob2','org-acme','u-bob','user','org','org-acme','r-owner')`)
	if _, err := call(d, alice, "org-acme", "membership.delete", map[string]string{"id": "m-alice", "org_id": "org-acme"}); err != nil {
		t.Fatalf("remove one of two owners: %v", err)
	}
	// A team-level owner role does not count as an org owner.
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES ('m-alice-t','org-acme','u-alice','user','team','t-ops','r-owner')`)
	if _, err := call(d, user("u-bob", ""), "org-acme", "member.remove", map[string]string{"org_id": "org-acme", "actor_id": "u-bob", "actor_type": "user", "resource_type": "org", "resource_id": "org-acme"}); !errors.Is(err, action.ErrLastOwner) {
		t.Errorf("last org owner with a team owner left: %v", err)
	}
	// An org id in the input cannot redirect the change to another org.
	if _, err := call(d, user("u-bob", ""), "org-acme", "membership.delete", map[string]string{"id": "m-admin", "org_id": "org-b"}); err != nil {
		t.Fatal(err)
	}
	if h.membership("org-b", "u-admin", "org", "org-b") == "" {
		t.Fatal("membership.delete reached another org through its input")
	}
}

func TestLastOwnerSCIMDeactivation(t *testing.T) {
	h, _, _, tokA, _ := wu611Setup(t, smOpts{})
	d, _ := orgDispatcher(h)
	r := h.scim(tokA, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "olive@corp.example", "active": true})
	expectSCIM(t, "create", r, http.StatusCreated, "")
	olive := h.scimUser(r.str("id"))
	// Olive becomes the only owner; she also holds a team membership and a key.
	h.exec(`UPDATE memberships SET role_id='r-owner' WHERE org_id='org-acme' AND actor_id=? AND resource_type='org'`, olive)
	h.exec(`UPDATE memberships SET role_id='r-member' WHERE id='m-alice'`)
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES ('m-olive-t','org-acme',?,'user','team','t-ops','r-member')`, olive)
	createKey(t, d, user(olive, ""), "org-acme", map[string]any{"name": "olive-key"}, "")
	raw, _, err := h.newSession(olive)
	if err != nil {
		t.Fatal(err)
	}

	r = h.scim(tokA, http.MethodPatch, "/scim/v2/Users/"+r.str("id"), map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	})
	expectSCIM(t, "deactivate", r, http.StatusOK, "")
	if got := h.membership("org-acme", olive, "org", "org-acme"); got != "r-owner/scim" {
		t.Fatalf("owner membership: %q", got)
	}
	if h.membership("org-acme", olive, "team", "t-ops") != "" {
		t.Error("other memberships kept")
	}
	if h.n(`SELECT COUNT(*) FROM api_keys WHERE user_id=? AND revoked_at IS NULL`, olive) != 0 {
		t.Error("API key not revoked")
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashOf(raw)) != 0 {
		t.Error("session kept by the preserved membership")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='membership.last_owner_preserved' AND org_id='org-acme' AND subject=? AND detail_json LIKE '%"via":"scim"%'`, olive) != 1 {
		t.Error("not audited")
	}
	// Once someone else owns the org, deactivation removes it.
	h.exec(`UPDATE memberships SET role_id='r-owner' WHERE id='m-alice'`)
	expectSCIM(t, "reactivate", h.scim(tokA, http.MethodPatch, "/scim/v2/Users/"+h.str(`SELECT id FROM scim_users WHERE user_id=?`, olive), map[string]any{
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}},
	}), http.StatusOK, "")
	expectSCIM(t, "delete", h.scim(tokA, http.MethodDelete, "/scim/v2/Users/"+h.str(`SELECT id FROM scim_users WHERE user_id=?`, olive), nil), http.StatusNoContent, "")
	if h.membership("org-acme", olive, "org", "org-acme") != "" {
		t.Error("membership kept when not the last owner")
	}
}

func TestLastOwnerGroupSync(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	// Carol's owner membership comes from the IdP; she is the only owner.
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-carol','carol@corp.example','Carol')`)
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id, source) VALUES ('m-carol','org-acme','u-carol','user','org','org-acme','r-owner','idp')`)
	h.exec(`INSERT INTO idp_group_mappings (id, org_id, group_value, role_id, resource_type, resource_id) VALUES
		('g-own','org-acme','Owners','r-owner','org','org-acme'), ('g-mem','org-acme','Staff','r-member','org','org-acme')`)
	h.exec(`UPDATE memberships SET role_id='r-member' WHERE id='m-alice'`)
	sync := func(groups ...string) action.SyncResult {
		t.Helper()
		tx, err := h.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		res, err := action.ReconcileIdPMemberships(context.Background(), sqlc.New(tx), action.SyncInput{
			OrgID: "org-acme", UserID: "u-carol", ProviderID: "acme-sso", Groups: groups, Actor: user("u-carol", ""),
		})
		if err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return res
	}
	// Removed from every group: the last owner membership stays.
	if res := sync(); len(res.Removed) != 0 || len(res.Kept) != 1 {
		t.Fatalf("removal: %+v", res)
	}
	// Moved to a non-owner group: no demotion either.
	if res := sync("Staff"); len(res.Updated) != 0 || len(res.Kept) != 1 {
		t.Fatalf("demotion: %+v", res)
	}
	if h.membership("org-acme", "u-carol", "org", "org-acme") != "r-owner/idp" {
		t.Fatal("last owner removed or demoted by sync")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='membership.last_owner_preserved' AND detail_json LIKE '%"via":"group_sync"%'`) != 2 {
		t.Error("not audited")
	}
	// With another owner, sync demotes as usual.
	h.exec(`UPDATE memberships SET role_id='r-owner' WHERE id='m-alice'`)
	if res := sync("Staff"); len(res.Updated) != 1 {
		t.Fatalf("with another owner: %+v", res)
	}
	if h.membership("org-acme", "u-carol", "org", "org-acme") != "r-member/idp" {
		t.Fatal("not demoted")
	}
}

// enforceSSO turns on org-acme's SSO requirement (provider acme-sso).
func (h *smHarness) enforceSSO() {
	h.exec(`INSERT INTO org_sso_settings (org_id, enforce_sso) VALUES ('org-acme', 1)`)
}

// streamFirst opens /events with the session raw and returns the first
// data frame after publishing evs (repeatedly, until one arrives).
func (h *smHarness) streamFirst(raw string, evs ...event.Event) string {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.app.URL+"/events", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: raw})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("/events: %d", resp.StatusCode)
	}
	go func() {
		for i := 0; i < 50 && ctx.Err() == nil; i++ {
			for _, ev := range evs {
				h.srv.Bus().Publish(ev)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return readFirstFrame(h.t, resp.Body)
}

func TestSSEHonoursOrgSSO(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.srv.RunHubForTest(ctx)
	h.enforceSSO()
	acmeEv := event.Event{Name: "task.update", Org: "org-acme", Subject: "acme-task"}
	marker := event.Event{Name: "platform.marker", Subject: "marker"}

	// bob (member of org-acme) signed in with Google: the org's events are
	// not delivered; the platform-wide marker is.
	viaGoogle, _ := h.sessionVia(oidctest.NewBrowser(t), "u-bob", "google")
	if got := h.streamFirst(viaGoogle, acmeEv, marker); strings.Contains(got, "acme-task") || !strings.Contains(got, "marker") {
		t.Fatalf("non-SSO session got: %q", got)
	}
	// After signing in through the org's provider they are.
	viaSSO, _ := h.sessionVia(oidctest.NewBrowser(t), "u-bob", "acme-sso")
	if got := h.streamFirst(viaSSO, acmeEv); !strings.Contains(got, "acme-task") {
		t.Fatalf("SSO session got: %q", got)
	}
	// An org without enforcement is unaffected.
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES ('m-bob-b','org-b','u-bob','user','org','org-b','r-bowner')`)
	viaGoogle2, _ := h.sessionVia(oidctest.NewBrowser(t), "u-bob", "google")
	if got := h.streamFirst(viaGoogle2, event.Event{Name: "task.update", Org: "org-b", Subject: "beta-task"}); !strings.Contains(got, "beta-task") {
		t.Fatalf("unenforced org: %q", got)
	}
}

func TestChatOrgListHonoursOrgSSO(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	h.enforceSSO()
	// bob belongs only to the enforcing org-acme: chat refuses with the SSO page.
	b := oidctest.NewBrowser(t)
	h.sessionVia(b, "u-bob", "google")
	status, _, page := h.get(b, "/app/chat")
	if status != http.StatusForbidden || !strings.Contains(page, "requires single sign-on") || !strings.Contains(page, "/auth/acme-sso") {
		t.Fatalf("chat, enforced only: %d %s", status, page)
	}
	if status, _, _ := h.get(b, "/app/chat/sessions-partial?org_id=org-acme&kind=org"); status != http.StatusForbidden {
		t.Errorf("sessions partial for the enforced org: %d", status)
	}
	if status, _, _ := h.get(b, "/app/chat/sessions-partial?org_id=org-b&kind=org"); status != http.StatusForbidden {
		t.Errorf("sessions partial for a non-member org: %d", status)
	}
	// With a second, unenforced org, only that one is offered.
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES ('m-bob-b','org-b','u-bob','user','org','org-b','r-bowner')`)
	status, _, page = h.get(b, "/app/chat")
	if status != http.StatusOK || strings.Contains(page, `"org-acme"`) || !strings.Contains(page, `data-scope-org="org-b"`) {
		t.Fatalf("chat, mixed: %d %s", status, page)
	}
	// Signed in through the org's provider, org-acme is back.
	b2 := oidctest.NewBrowser(t)
	h.sessionVia(b2, "u-bob", "acme-sso")
	if _, _, page := h.get(b2, "/app/chat"); !strings.Contains(page, `"org-acme"`) {
		t.Errorf("SSO session lacks org-acme: %s", page)
	}
	if status, _, _ := h.get(b2, "/app/chat/sessions-partial?org_id=org-acme&kind=org"); status != http.StatusOK {
		t.Errorf("sessions partial via SSO: %d", status)
	}
}
