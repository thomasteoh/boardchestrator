package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/idp"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/perm"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// WU-607: organisation-owned identity providers (org.idp.*), email trust
// bounded by the org's verified domains, org.sso.* and SSO enforcement in
// dispatch and on org pages.

// recordingSink keeps every emitted event and forwards it to next.
type recordingSink struct {
	mu   sync.Mutex
	evs  []action.Event
	next action.EventSink
}

func (s *recordingSink) Emit(ctx context.Context, ev action.Event) {
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
	if s.next != nil {
		s.next.Emit(ctx, ev)
	}
}

func (s *recordingSink) all() []action.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]action.Event(nil), s.evs...)
}

// orgDispatcher is ssoDispatcher with events reaching the server bus (so the
// registry invalidates) through a recorder.
func orgDispatcher(h *smHarness) (*action.Dispatcher, *recordingSink) {
	rec := &recordingSink{next: h.srv.EventSink()}
	return action.New(h.db,
		action.WithScopeResolver(action.NewDBScopeResolver(h.db)),
		action.WithPermissionChecker(perm.NewCheckerAdapter(h.db)),
		action.WithSecretKey(tenant.PadKey(testConfig().SecretKey)),
		action.WithEventSink(rec),
	), rec
}

func call(d *action.Dispatcher, actor action.Actor, org, name string, in any) (any, error) {
	raw, _ := json.Marshal(in)
	return d.Dispatch(context.Background(), actor, name, raw, action.Opts{Org: org})
}

func user(id, provider string) action.Actor {
	return action.Actor{Type: action.ActorUser, ID: id, IP: "192.0.2.7", AuthProviderID: provider}
}

// orgIdP inserts an org-owned OIDC provider row directly.
func (h *smHarness) orgIdP(id, orgID string, srv *oidctest.Server, trust, signup bool) {
	h.t.Helper()
	enc, err := tenant.Encrypt(tenant.PadKey(testConfig().SecretKey), srv.ClientSecret)
	if err != nil {
		h.t.Fatal(err)
	}
	b := map[bool]int{false: 0, true: 1}
	if _, err := h.db.Exec(`INSERT INTO auth_providers (id, org_id, kind, preset, display_name, enabled, managed_by,
		issuer, client_id, client_secret_enc, trust_email, allow_signup) VALUES (?, ?, 'oidc', 'generic', ?, 1, 'ui', ?, ?, ?, ?, ?)`,
		id, orgID, "Acme SSO", srv.Issuer(), srv.ClientID, enc, b[trust], b[signup]); err != nil {
		h.t.Fatal(err)
	}
	h.srv.IdP().Invalidate()
}

func (h *smHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.Exec(q, args...); err != nil {
		h.t.Fatalf("%v\n%s", err, q)
	}
}

// signIn runs a full login through provider and returns the final step.
func (h *smHarness) signIn(b *oidctest.Browser, provider string) oidctest.Step {
	h.t.Helper()
	return h.follow(b, "/auth/"+provider)
}

func TestOrgProviderEmailTrust(t *testing.T) {
	h := newSMHarness(t, smOpts{adminEmails: []string{"root@corp.example"}})
	seedSSOOrgs(t, h)
	acme := oidctest.New(t)
	// trust_email on and allow_signup forced on in the row: the registry
	// must still refuse open sign-up for an org-owned provider.
	h.orgIdP("acme-sso", "org-acme", acme, true, true)
	h.verifiedDomain("org-acme", "corp.example", true)
	h.verifiedDomain("org-b", "beta.example", true)
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-carol','carol@corp.example','Carol'),
		('u-erin','erin@beta.example','Erin'), ('u-root','root@corp.example','Root')`)

	identities := func(sub string) int {
		return h.n(`SELECT COUNT(*) FROM identities WHERE provider='acme-sso' AND subject=?`, sub)
	}
	// Outside the org's verified domains: never links, even trusted+verified.
	users := h.n(realUsers)
	acme.SetUser(oidctest.User{Subject: "s-bob", Email: "bob@example.com", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusForbidden {
		t.Fatalf("outside domain: %d", end.Status)
	}
	// On a domain another org verified: never links either.
	acme.SetUser(oidctest.User{Subject: "s-erin", Email: "erin@beta.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusForbidden {
		t.Fatalf("other org's domain: %d", end.Status)
	}
	if identities("s-bob")+identities("s-erin") != 0 || h.n(realUsers) != users {
		t.Fatal("org provider linked or created a user outside its verified domains")
	}
	// No account on the verified domain, no invite: open sign-up is
	// impossible for an org provider.
	acme.SetUser(oidctest.User{Subject: "s-dave", Email: "dave@corp.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusForbidden {
		t.Fatalf("open sign-up via org provider: %d", end.Status)
	}
	if identities("s-dave") != 0 || h.n(realUsers) != users {
		t.Fatal("org provider signed someone up without an invite")
	}
	// With an invite it signs up.
	tok := h.invite("dave@corp.example", future(), false)
	if end := h.follow(oidctest.NewBrowser(t), "/auth/acme-sso?invite="+url.QueryEscape(tok)); end.Status != http.StatusOK {
		t.Fatalf("invite sign-up: %d %q", end.Status, end.Body)
	}
	if identities("s-dave") != 1 {
		t.Fatal("invite sign-up did not create the identity")
	}
	// Inside a verified domain with trust_email: links.
	acme.SetUser(oidctest.User{Subject: "s-carol", Email: "carol@corp.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("verified-domain link: %d", end.Status)
	}
	if h.n(`SELECT COUNT(*) FROM identities WHERE provider='acme-sso' AND subject='s-carol' AND user_id='u-carol'`) != 1 {
		t.Fatal("trusted org provider did not link on its verified domain")
	}
	// Unverified email on the verified domain: no link.
	acme.SetUser(oidctest.User{Subject: "s-carol2", Email: "carol@corp.example", EmailVerified: false})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusForbidden || identities("s-carol2") != 0 {
		t.Fatalf("unverified email linked: %d", end.Status)
	}
	// An org provider asserting a BC_ADMIN_EMAILS address never grants
	// platform admin.
	acme.SetUser(oidctest.User{Subject: "s-root", Email: "root@corp.example", EmailVerified: true})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("root via org provider: %d", end.Status)
	}
	if n := h.n(`SELECT COUNT(*) FROM memberships WHERE org_id=? AND actor_id='u-root'`, perm.PlatformOrg); n != 0 {
		t.Fatal("org provider granted platform admin through BC_ADMIN_EMAILS")
	}
	// Identity hit works for the org provider like any other.
	acme.SetUser(oidctest.User{Subject: "s-carol", Email: "whatever@else.example", EmailVerified: false})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("identity hit: %d", end.Status)
	}
}

func TestOrgIdPActions(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	d, rec := orgDispatcher(h)
	acme := oidctest.New(t)
	alice, bob, bOwner := user("u-alice", ""), user("u-bob", ""), user("u-admin", "")
	const secret = "s3cret-value-never-shown"
	in := func(id string) map[string]any {
		return map[string]any{"id": id, "preset": "generic", "params": map[string]string{"issuer": acme.Issuer()},
			"client_id": acme.ClientID, "client_secret": secret, "trust_email": true}
	}

	// Registry loaded before the create, so the create must invalidate it.
	if _, err := h.srv.IdP().Providers(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		in   map[string]any
	}{
		{"no prefix", in("corp-sso")},
		{"bare prefix", in("acme-")},
		{"github", map[string]any{"id": "acme-gh", "preset": "github", "client_id": "x", "client_secret": "y"}},
		{"open signup", func() map[string]any { m := in("acme-open"); m["allow_signup"] = true; return m }()},
	} {
		if _, err := call(d, alice, "org-acme", idp.ActionOrgCreate, c.in); !errors.Is(err, action.ErrInvalidInput) {
			t.Errorf("create %s: %v", c.name, err)
		}
	}
	out, err := call(d, alice, "org-acme", idp.ActionOrgCreate, in("acme-sso"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if b, _ := json.Marshal(out); strings.Contains(string(b), secret) {
		t.Fatal("secret in result")
	}
	if _, err := call(d, alice, "org-acme", idp.ActionOrgCreate, in("acme-sso")); !errors.Is(err, action.ErrInvalidInput) {
		t.Fatalf("duplicate id: %v", err)
	}
	if n := h.n(`SELECT COUNT(*) FROM auth_providers WHERE id='acme-sso' AND org_id='org-acme' AND allow_signup=0`); n != 1 {
		t.Fatal("org provider row not stored as org-owned without sign-up")
	}
	// The registry picks it up through the org.idp.create event.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ps, _ := h.srv.IdP().Providers(context.Background())
		found := false
		for _, p := range ps {
			found = found || (p.ID == "acme-sso" && p.OrgID == "org-acme")
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("registry not invalidated by org.idp.create")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Org B's owner cannot see or touch it; nor platform providers.
	lst, err := call(d, bOwner, "org-b", idp.ActionOrgList, struct{}{})
	if err != nil || len(lst.([]idp.ProviderView)) != 0 {
		t.Fatalf("org B list: %v %v", lst, err)
	}
	for _, name := range []string{idp.ActionOrgGet, idp.ActionOrgDisable, idp.ActionOrgEnable, idp.ActionOrgDelete} {
		for _, id := range []string{"acme-sso", "google", "corp"} {
			if _, err := call(d, bOwner, "org-b", name, map[string]string{"id": id}); !errors.Is(err, action.ErrInvalidInput) {
				t.Errorf("org B %s %s: %v", name, id, err)
			}
		}
	}
	upd := in("acme-sso")
	upd["display_name"] = "Hijacked"
	if _, err := call(d, bOwner, "org-b", idp.ActionOrgUpdate, upd); !errors.Is(err, action.ErrInvalidInput) {
		t.Errorf("org B update: %v", err)
	}
	// Org B's owner naming org A in the call is refused by scope/permission.
	if _, err := call(d, bOwner, "org-acme", idp.ActionOrgList, struct{}{}); !errors.Is(err, action.ErrForbidden) {
		t.Errorf("org B owner listing org A: %v", err)
	}
	// Alice cannot reach platform providers through org.idp.* either.
	if _, err := call(d, alice, "org-acme", idp.ActionOrgGet, map[string]string{"id": "google"}); !errors.Is(err, action.ErrInvalidInput) {
		t.Errorf("org get of platform provider: %v", err)
	}
	// Bob is a member without org.sso.
	if _, err := call(d, bob, "org-acme", idp.ActionOrgList, struct{}{}); !errors.Is(err, action.ErrForbidden) {
		t.Errorf("member without org.sso: %v", err)
	}
	// Alice's list shows only her org's provider, without its secret.
	lst, err = call(d, alice, "org-acme", idp.ActionOrgList, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	views := lst.([]idp.ProviderView)
	if len(views) != 1 || views[0].ID != "acme-sso" || !views[0].SecretSet || views[0].AllowSignup {
		t.Fatalf("list: %+v", views)
	}
	if _, err := call(d, alice, "org-acme", idp.ActionOrgUpdate, upd); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Discovery through the org guard works when private addresses are
	// allowed (this harness) for a saved provider.
	res, err := call(d, alice, "org-acme", idp.ActionOrgDiscover, map[string]string{"id": "acme-sso"})
	if r, _ := res.(idp.DiscoverResult); err != nil || !r.OK {
		t.Fatalf("discover allowed: %+v %v", res, err)
	}

	// No secret in events or audit rows.
	for _, ev := range rec.all() {
		if strings.Contains(string(ev.Payload), secret) {
			t.Errorf("secret in %s event", ev.Name)
		}
	}
	assertAuditClean(t, h, secret, acme.ClientSecret)
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='org.idp.create' AND org_id='org-acme'`) != 1 {
		t.Error("org.idp.create not audited")
	}
	// Platform idp.list never shows org rows.
	if err := grantPlatformOwner(h, "u-admin"); err != nil {
		t.Fatal(err)
	}
	pl, err := call(d, bOwner, "", idp.ActionList, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range pl.([]idp.ProviderView) {
		if v.ID == "acme-sso" {
			t.Error("platform idp.list shows an org provider")
		}
	}
}

func grantPlatformOwner(h *smHarness, userID string) error {
	_, err := h.db.Exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id)
		VALUES (?, ?, ?, 'user', 'org', ?, ?)`, "m-po-"+userID, perm.PlatformOrg, userID, perm.PlatformOrg, perm.PlatformOwnerRole)
	return err
}

func TestOrgIdPPrivateAddressesBlockedByDefault(t *testing.T) {
	h := newSMHarness(t, smOpts{blockOrgPrivate: true})
	seedSSOOrgs(t, h)
	d, _ := orgDispatcher(h)
	acme := oidctest.New(t) // listens on 127.0.0.1
	res, err := call(d, user("u-alice", ""), "org-acme", idp.ActionOrgDiscover,
		map[string]any{"preset": "generic", "params": map[string]string{"issuer": acme.Issuer()}})
	r, _ := res.(idp.DiscoverResult)
	if err != nil || r.OK || r.Ref == "" || r.TokenEndpoint != "" {
		t.Fatalf("org discovery of a loopback issuer: %+v %v", res, err)
	}
	// Platform discovery (Q9) still reaches it.
	if err := grantPlatformOwner(h, "u-admin"); err != nil {
		t.Fatal(err)
	}
	res, err = call(d, user("u-admin", ""), "", idp.ActionDiscover,
		map[string]any{"preset": "generic", "params": map[string]string{"issuer": acme.Issuer()}})
	if r, _ := res.(idp.DiscoverResult); err != nil || !r.OK {
		t.Fatalf("platform discovery: %+v %v", res, err)
	}
	// Sign-in through an org provider on a loopback issuer fails too: the
	// registry's org client refuses the discovery fetch.
	h.orgIdP("acme-sso", "org-acme", acme, true, false)
	b := oidctest.NewBrowser(t)
	steps, _ := b.Follow(h.app.URL+"/auth/acme-sso", 4, nil)
	if len(steps) == 0 || steps[len(steps)-1].Status == http.StatusOK || len(acme.AuthorizeRequests()) != 0 {
		t.Fatalf("org login reached a loopback IdP: %+v", steps)
	}
}

func TestSSOEnforcement(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	d, _ := orgDispatcher(h)
	acme := oidctest.New(t)
	h.orgIdP("acme-sso", "org-acme", acme, true, false)
	h.verifiedDomain("org-acme", "example.com", true)
	// Bob may read the org's SSO settings, so he has an org action to try.
	h.exec(`UPDATE roles SET grants_json='["task.*","org.sso"]' WHERE id='r-member'`)

	// Lock-out guard: Alice signed in with Google cannot turn it on.
	if _, err := call(d, user("u-alice", "google"), "org-acme", "org.sso.update", map[string]bool{"enforce_sso": true}); !errors.Is(err, action.ErrSSOLockout) {
		t.Fatalf("enable from Google session: %v", err)
	}
	if _, err := call(d, user("u-alice", ""), "org-acme", "org.sso.update", map[string]bool{"enforce_sso": true}); !errors.Is(err, action.ErrSSOLockout) {
		t.Fatalf("enable from session without provider: %v", err)
	}
	// Same through the page: Alice signs in with Google, posts the toggle.
	h.google.SetUser(oidctest.User{Subject: "alice-g", Email: "alice@example.com", EmailVerified: true})
	ab := oidctest.NewBrowser(t)
	if end := h.signIn(ab, "google"); end.Status != http.StatusOK {
		t.Fatalf("alice google: %d", end.Status)
	}
	_, _, page := h.get(ab, "/app/org/org-acme/settings/sso")
	if !strings.Contains(page, "Identity provider") || !strings.Contains(page, "acme-sso/callback") ||
		!strings.Contains(page, "so you can&#39;t lock yourself out") {
		t.Fatalf("SSO page sections missing:\n%s", page)
	}
	resp := h.postForm(ab, "/app/org/org-acme/settings/sso/enforcement", h.csrfOf(ab), url.Values{"enforce_sso": {"1"}})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "?error=lockout") {
		t.Fatalf("enforce from Google session via page: %d %q", resp.StatusCode, loc)
	}
	if h.n(`SELECT COUNT(*) FROM org_sso_settings WHERE enforce_sso=1`) != 0 {
		t.Fatal("enforcement enabled despite the lock-out guard")
	}
	// Signed in through the org IdP, she can.
	acme.SetUser(oidctest.User{Subject: "alice-acme", Email: "alice@example.com", EmailVerified: true})
	if end := h.signIn(ab, "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("alice acme: %d", end.Status)
	}
	resp = h.postForm(ab, "/app/org/org-acme/settings/sso/enforcement", h.csrfOf(ab), url.Values{"enforce_sso": {"1"}})
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, "?notice=enforced") {
		t.Fatalf("enforce from SSO session: %d %q", resp.StatusCode, loc)
	}
	if h.n(`SELECT COUNT(*) FROM org_sso_settings WHERE org_id='org-acme' AND enforce_sso=1`) != 1 {
		t.Fatal("enforcement not stored")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='org.sso.update' AND org_id='org-acme'`) != 1 {
		t.Error("org.sso.update not audited")
	}

	// Dispatch: Bob via Google is refused with ErrSSORequired; via the org
	// IdP he is allowed.
	_, err := call(d, user("u-bob", "google"), "org-acme", "org.sso.get", struct{}{})
	var sso action.ErrSSORequired
	if !errors.As(err, &sso) || sso.OrgID != "org-acme" || len(sso.Providers) != 1 || sso.Providers[0] != "acme-sso" ||
		!errors.Is(err, action.ErrForbidden) {
		t.Fatalf("bob via google: %v", err)
	}
	if _, err := call(d, user("u-bob", "acme-sso"), "org-acme", "org.sso.get", struct{}{}); err != nil {
		t.Fatalf("bob via org IdP: %v", err)
	}
	// A provider of another org does not satisfy it.
	h.orgIdP("beta-sso", "org-b", oidctest.New(t), true, false)
	if _, err := call(d, user("u-bob", "beta-sso"), "org-acme", "org.sso.get", struct{}{}); !errors.As(err, &sso) {
		t.Fatalf("bob via another org's IdP: %v", err)
	}
	// Team/project-scoped actions in the org are covered too.
	h.exec(`INSERT INTO projects (id, org_id, name, key) VALUES ('p-acme','org-acme','Web','WEB')`)
	raw, _ := json.Marshal(map[string]string{"title": "x"})
	if _, err := d.Dispatch(context.Background(), user("u-bob", "google"), "task.create", raw,
		action.Opts{Org: "org-acme", Proj: "p-acme"}); !errors.As(err, &sso) {
		t.Fatalf("project action via google: %v", err)
	}
	// API keys and agents are not subject to it (whatever else refuses them).
	for _, a := range []action.Actor{
		{Type: action.ActorAPIKey, ID: "k-1", OwnerUserID: "u-bob"},
		{Type: action.ActorAgent, ID: "agent-1"},
	} {
		if _, err := call(d, a, "org-acme", "org.sso.get", struct{}{}); errors.As(err, &sso) {
			t.Errorf("%s actor got ErrSSORequired", a.Type)
		}
	}
	// Other orgs unaffected: org B's owner with a Google session.
	if _, err := call(d, user("u-admin", "google"), "org-b", "org.domain.list", struct{}{}); err != nil {
		t.Fatalf("org B unaffected: %v", err)
	}
	// Last enabled provider cannot be disabled or deleted while enforced.
	if _, err := call(d, user("u-alice", "acme-sso"), "org-acme", idp.ActionOrgDisable, map[string]string{"id": "acme-sso"}); !errors.Is(err, idp.ErrLastEnforcedProvider) {
		t.Fatalf("disable last provider: %v", err)
	}

	// Web: Bob signed in with Google gets the SSO-required page on org
	// pages, project pages and the generic action endpoint.
	bb := oidctest.NewBrowser(t)
	h.google.SetUser(oidctest.User{Subject: "bob-g", Email: "bob@example.com", EmailVerified: true})
	if end := h.signIn(bb, "google"); end.Status != http.StatusOK {
		t.Fatalf("bob google: %d", end.Status)
	}
	for _, p := range []string{"/app/org/org-acme/settings", "/app/org/org-acme/settings/sso", "/app/project/p-acme/board/partial"} {
		status, _, body := h.get(bb, p)
		if status != http.StatusForbidden || !strings.Contains(body, "This organisation requires single sign-on") ||
			!strings.Contains(body, `href="/auth/acme-sso?return_to=`) {
			t.Fatalf("GET %s via google: %d\n%s", p, status, body)
		}
	}
	_, _, body := h.get(bb, "/app/org/org-acme/settings")
	if !strings.Contains(body, url.QueryEscape("/app/org/org-acme/settings")) {
		t.Error("SSO-required link does not return to the page")
	}
	csrf := h.csrfOf(bb)
	req, _ := http.NewRequest(http.MethodPost, h.app.URL+"/api/action/webhook.list", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-Id", "org-acme")
	req.Header.Set("X-CSRF-Token", csrf)
	if resp, err := bb.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("web action via google: %v %v", resp, err)
	}
	// Other orgs' pages are not gated by org A's policy.
	if status, _, body := h.get(bb, "/app/org/org-b/settings"); strings.Contains(body, "requires single sign-on") {
		t.Fatalf("org B page gated: %d", status)
	}
	// After signing in through the org IdP, the page opens.
	acme.SetUser(oidctest.User{Subject: "bob-acme", Email: "bob@example.com", EmailVerified: true})
	if end := h.signIn(bb, "acme-sso"); end.Status != http.StatusOK {
		t.Fatalf("bob acme: %d", end.Status)
	}
	if status, _, body := h.get(bb, "/app/org/org-acme/settings"); status != http.StatusOK || strings.Contains(body, "requires single sign-on") {
		t.Fatalf("org page after SSO: %d", status)
	}

	// Break-glass: a platform owner with a Google session keeps access.
	if err := grantPlatformOwner(h, "u-admin"); err != nil {
		t.Fatal(err)
	}
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id)
		VALUES ('m-admin-acme','org-acme','u-admin','user','org','org-acme','r-owner')`)
	if _, err := call(d, user("u-admin", "google"), "org-acme", "org.sso.update", map[string]bool{"enforce_sso": false}); err != nil {
		t.Fatalf("platform owner break-glass: %v", err)
	}
}

// csrfOf is the CSRF token for b's current session cookie.
func (h *smHarness) csrfOf(b *oidctest.Browser) string {
	h.t.Helper()
	c := b.Cookie(h.app.URL, auth.CookieName)
	if c == nil {
		h.t.Fatal("no session cookie")
	}
	return auth.CSRFToken(smSessionSecret, hashOf(c.Value))
}

func TestOrgIdPPages(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	acme := oidctest.New(t)
	b := oidctest.NewBrowser(t)
	_, csrf := h.signedIn(b, "u-alice")

	status, _, page := h.get(b, "/app/org/org-acme/settings/sso/providers/new?preset=microsoft")
	if status != http.StatusOK || !strings.Contains(page, `value="acme-"`) || strings.Contains(page, `name="allow_signup"`) ||
		!strings.Contains(page, "only for addresses on this organisation") {
		t.Fatalf("new form: %d\n%s", status, page)
	}
	// GitHub is not offered to organisations.
	if _, _, page := h.get(b, "/app/org/org-acme/settings/sso"); strings.Contains(page, "providers/new?preset=github") {
		t.Error("GitHub offered as an organisation IdP")
	}
	form := url.Values{"preset": {"generic"}, "id": {"acme-okta"}, "param_issuer": {acme.Issuer()},
		"client_id": {acme.ClientID}, "client_secret": {"form-secret-xyz"}, "trust_email": {"1"},
		"allow_signup": {"1"}, "enabled": {"1"}}
	resp := h.postForm(b, "/app/org/org-acme/settings/sso/providers", csrf, form)
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || !strings.HasSuffix(loc, "?notice=idp_created") {
		t.Fatalf("create via page: %d %q", resp.StatusCode, loc)
	}
	if h.n(`SELECT COUNT(*) FROM auth_providers WHERE id='acme-okta' AND org_id='org-acme' AND allow_signup=0 AND trust_email=1`) != 1 {
		t.Fatal("page did not create the org provider (without sign-up)")
	}
	_, _, page = h.get(b, "/app/org/org-acme/settings/sso")
	if !strings.Contains(page, "/auth/acme-okta/callback") || strings.Contains(page, "form-secret-xyz") {
		t.Fatal("SSO page: callback URL missing or secret shown")
	}
	// Bob (no org.sso) cannot use the pages; org B's owner cannot reach org A's.
	bb := oidctest.NewBrowser(t)
	_, bcsrf := h.signedIn(bb, "u-bob")
	if status, _, _ := h.get(bb, "/app/org/org-acme/settings/sso/providers/acme-okta/edit"); status != http.StatusForbidden {
		t.Errorf("bob edit page: %d", status)
	}
	if r := h.postForm(bb, "/app/org/org-acme/settings/sso/providers/acme-okta/disable", bcsrf, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("bob disable: %d", r.StatusCode)
	}
	ob := oidctest.NewBrowser(t)
	_, ocsrf := h.signedIn(ob, "u-admin")
	if r := h.postForm(ob, "/app/org/org-b/settings/sso/providers/acme-okta/disable", ocsrf, nil); !strings.HasSuffix(r.Header.Get("Location"), "error=idp_not_found") {
		t.Errorf("org B disabling org A's provider: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if h.n(`SELECT enabled FROM auth_providers WHERE id='acme-okta'`) != 1 {
		t.Fatal("provider disabled by an outsider")
	}
}
