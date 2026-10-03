package server_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/perm"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// WU-606: org email domains (org.domain.*), Org settings -> Single sign-on,
// and home-realm discovery on /login.

// fakeTXT is an injectable TXT resolver: records by name, or an error.
type fakeTXT struct {
	mu        sync.Mutex
	records   map[string][]string
	err       error
	deadlines []time.Duration
}

func (f *fakeTXT) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if dl, ok := ctx.Deadline(); ok {
		f.deadlines = append(f.deadlines, time.Until(dl))
	} else {
		f.deadlines = append(f.deadlines, -1)
	}
	if f.err != nil {
		return nil, f.err
	}
	if recs, ok := f.records[name]; ok {
		return recs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeTXT) set(name string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[name] = values
}

func (f *fakeTXT) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func installFakeTXT(t *testing.T) *fakeTXT {
	t.Helper()
	f := &fakeTXT{records: map[string][]string{}}
	action.SetTXTResolver(f)
	t.Cleanup(func() { action.SetTXTResolver(nil) })
	return f
}

// seedSSOOrgs: Alice owns org-acme, Bob is a plain member of it (no
// org.sso), Admin owns org-b.
func seedSSOOrgs(t *testing.T, h *smHarness) {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO orgs (id, name, slug) VALUES ('org-b','Beta','beta')`,
		`INSERT INTO roles (id, org_id, name, is_system, grants_json) VALUES
		 ('r-owner','org-acme','Owner',0,'["*"]'), ('r-bowner','org-b','Owner',0,'["*"]')`,
		`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES
		 ('m-alice','org-acme','u-alice','user','org','org-acme','r-owner'),
		 ('m-bob','org-acme','u-bob','user','org','org-acme','r-member'),
		 ('m-admin','org-b','u-admin','user','org','org-b','r-bowner')`,
	} {
		if _, err := h.db.Exec(q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
}

func ssoDispatcher(h *smHarness) *action.Dispatcher {
	return action.New(h.db,
		action.WithScopeResolver(action.NewDBScopeResolver(h.db)),
		action.WithPermissionChecker(perm.NewCheckerAdapter(h.db)),
		action.WithSecretKey(tenant.PadKey(testConfig().SecretKey)),
	)
}

func dispatchAs(t *testing.T, d *action.Dispatcher, user, org, name string, in map[string]string) (action.OrgDomainView, error) {
	t.Helper()
	raw, _ := json.Marshal(in)
	out, err := d.Dispatch(context.Background(), action.Actor{Type: action.ActorUser, ID: user, IP: "192.0.2.1"},
		name, raw, action.Opts{Org: org})
	var v action.OrgDomainView
	if err == nil {
		b, _ := json.Marshal(out)
		_ = json.Unmarshal(b, &v)
	}
	return v, err
}

func listDomains(t *testing.T, d *action.Dispatcher, user, org string) ([]action.OrgDomainView, error) {
	t.Helper()
	out, err := d.Dispatch(context.Background(), action.Actor{Type: action.ActorUser, ID: user},
		"org.domain.list", json.RawMessage(`{}`), action.Opts{Org: org})
	if err != nil {
		return nil, err
	}
	var l struct {
		Domains []action.OrgDomainView `json:"domains"`
	}
	b, _ := json.Marshal(out)
	_ = json.Unmarshal(b, &l)
	return l.Domains, nil
}

func TestOrgDomainVerification(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	dns := installFakeTXT(t)
	d := ssoDispatcher(h)

	a, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.add", map[string]string{"domain": " Corp.EXAMPLE. "})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if a.Domain != "corp.example" || a.Status != "pending" ||
		a.RecordName != "_boardchestrator-challenge.corp.example" || !strings.HasPrefix(a.RecordValue, "bc-verify=") ||
		len(a.RecordValue) != len("bc-verify=")+32 {
		t.Fatalf("add result: %+v", a)
	}

	// No record, then a wrong value: not verified.
	if _, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.verify", map[string]string{"id": a.ID}); !errors.Is(err, action.ErrDomainRecordMissing) {
		t.Fatalf("verify without record: %v", err)
	}
	dns.set(a.RecordName, "v=spf1 -all", "bc-verify=0123456789abcdef0123456789abcdef")
	if _, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.verify", map[string]string{"id": a.ID}); !errors.Is(err, action.ErrDomainRecordMissing) {
		t.Fatalf("verify with wrong token: %v", err)
	}

	// Org B may hold a pending claim on the same domain; its token does not
	// verify org A's claim.
	b, err := dispatchAs(t, d, "u-admin", "org-b", "org.domain.add", map[string]string{"domain": "corp.example"})
	if err != nil || b.RecordValue == a.RecordValue {
		t.Fatalf("org B pending claim: %+v %v", b, err)
	}
	dns.set(a.RecordName, b.RecordValue)
	if _, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.verify", map[string]string{"id": a.ID}); !errors.Is(err, action.ErrDomainRecordMissing) {
		t.Fatalf("verify with the other org's token: %v", err)
	}
	if h.n(`SELECT COUNT(*) FROM org_domains WHERE verified_at IS NOT NULL`) != 0 {
		t.Fatal("something verified early")
	}

	// The right record (among others) verifies.
	dns.set(a.RecordName, "unrelated", a.RecordValue)
	v, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.verify", map[string]string{"id": a.ID})
	if err != nil || v.Status != "verified" || v.VerifiedAt == "" {
		t.Fatalf("verify: %+v %v", v, err)
	}
	if _, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.verify", map[string]string{"id": a.ID}); !errors.Is(err, action.ErrDomainAlreadyChecked) {
		t.Fatalf("re-verify: %v", err)
	}
	for _, dl := range dns.deadlines {
		if dl <= 0 || dl > action.DomainVerifyTimeout {
			t.Fatalf("lookup deadline %v, want within %v", dl, action.DomainVerifyTimeout)
		}
	}

	// Verified by A: B can neither verify its pending claim (even with its
	// own record published) nor add the domain again; C cannot add it.
	dns.set(a.RecordName, b.RecordValue)
	if _, err := dispatchAs(t, d, "u-admin", "org-b", "org.domain.verify", map[string]string{"id": b.ID}); !errors.Is(err, action.ErrDomainTaken) {
		t.Fatalf("org B verify after A: %v", err)
	}
	if _, err := dispatchAs(t, d, "u-admin", "org-b", "org.domain.add", map[string]string{"domain": "CORP.example"}); !errors.Is(err, action.ErrDomainTaken) {
		t.Fatalf("org B re-add: %v", err)
	}
	if _, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.add", map[string]string{"domain": "corp.example"}); !errors.Is(err, action.ErrDomainExists) {
		t.Fatalf("org A duplicate add: %v", err)
	}
	bl, err := listDomains(t, d, "u-admin", "org-b")
	if err != nil || len(bl) != 1 || bl[0].Status != "taken" || bl[0].RecordValue != "" {
		t.Fatalf("org B list: %+v %v", bl, err)
	}
	// Even bypassing the action, the database refuses a second verification.
	if _, err := h.db.Exec(`UPDATE org_domains SET verified_at = '2026-01-01T00:00:00.000Z' WHERE id = ?`, b.ID); err == nil {
		t.Fatal("partial unique index allowed two verified orgs")
	}

	// DNS failure is reported as a lookup error, not a missing record.
	c, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.add", map[string]string{"domain": "eng.corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	dns.fail(errors.New("i/o timeout"))
	if _, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.verify", map[string]string{"id": c.ID}); !errors.Is(err, action.ErrDomainLookup) {
		t.Fatalf("verify with DNS failure: %v", err)
	}
	dns.fail(nil)

	// Audit: add and verify are ImpactHigh dispatch rows in org A's log.
	for _, act := range []string{"org.domain.add", "org.domain.verify"} {
		if h.n(`SELECT COUNT(*) FROM audit_log WHERE org_id = 'org-acme' AND action = ? AND actor_id = 'u-alice'`, act) == 0 {
			t.Errorf("no %s audit row", act)
		}
	}
	if _, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.remove", map[string]string{"id": c.ID}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE org_id = 'org-acme' AND action = 'org.domain.remove' AND subject = ?`, c.ID) != 1 {
		t.Error("no org.domain.remove audit row")
	}
	if h.n(`SELECT COUNT(*) FROM org_domains WHERE id = ?`, c.ID) != 0 {
		t.Error("domain not removed")
	}
}

func TestOrgDomainNormalisationAndLimits(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	installFakeTXT(t)
	d := ssoDispatcher(h)
	for in, want := range map[string]string{
		"UPPER.Example.COM": "upper.example.com",
		"trailing.example.": "trailing.example",
		"bücher.example":    "xn--bcher-kva.example",
	} {
		v, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.add", map[string]string{"domain": in})
		if err != nil || v.Domain != want || v.RecordName != "_boardchestrator-challenge."+want {
			t.Errorf("add %q = %+v, %v; want %q", in, v, err, want)
		}
	}
	for in, want := range map[string]error{
		"192.0.2.7": action.ErrDomainIP, "[2001:db8::1]": action.ErrDomainIP,
		"com": action.ErrDomainInvalid, "co.uk": action.ErrDomainPublicSuffix,
		"localhost": action.ErrDomainInvalid, "a@b.example": action.ErrDomainInvalid, "": action.ErrDomainInvalid,
	} {
		if _, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.add", map[string]string{"domain": in}); !errors.Is(err, want) {
			t.Errorf("add %q: %v, want %v", in, err, want)
		}
	}
}

func TestOrgDomainAccessControl(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	dns := installFakeTXT(t)
	d := ssoDispatcher(h)
	a, err := dispatchAs(t, d, "u-alice", "org-acme", "org.domain.add", map[string]string{"domain": "acme.example"})
	if err != nil {
		t.Fatal(err)
	}
	dns.set(a.RecordName, a.RecordValue)

	// Bob is a member of org A without org.sso.
	if _, err := listDomains(t, d, "u-bob", "org-acme"); !errors.Is(err, action.ErrForbidden) {
		t.Errorf("member list: %v", err)
	}
	for _, c := range []struct {
		name string
		in   map[string]string
	}{
		{"org.domain.add", map[string]string{"domain": "bob.example"}},
		{"org.domain.verify", map[string]string{"id": a.ID}},
		{"org.domain.remove", map[string]string{"id": a.ID}},
	} {
		if _, err := dispatchAs(t, d, "u-bob", "org-acme", c.name, c.in); !errors.Is(err, action.ErrForbidden) {
			t.Errorf("member %s: %v", c.name, err)
		}
	}

	// Org B's owner: org A's scope is refused (not a member, so no grant),
	// and A's domain id
	// does not resolve inside org B.
	if _, err := listDomains(t, d, "u-admin", "org-acme"); !refused(err) {
		t.Errorf("org B listing org A: %v", err)
	}
	if bl, err := listDomains(t, d, "u-admin", "org-b"); err != nil || len(bl) != 0 {
		t.Errorf("org B sees %+v %v", bl, err)
	}
	for _, name := range []string{"org.domain.verify", "org.domain.remove"} {
		if _, err := dispatchAs(t, d, "u-admin", "org-acme", name, map[string]string{"id": a.ID}); !refused(err) {
			t.Errorf("org B %s in org A: %v", name, err)
		}
		if _, err := dispatchAs(t, d, "u-admin", "org-b", name, map[string]string{"id": a.ID}); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("org B %s of org A's id: %v", name, err)
		}
	}
	if h.n(`SELECT COUNT(*) FROM org_domains WHERE id = ? AND verified_at IS NULL`, a.ID) != 1 {
		t.Fatal("org A's domain changed by org B")
	}
	// Agents need an org.sso grant like anyone else; API-key/agent use is
	// covered by the generic permission engine tests.
}

func TestOrgSSOPage(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	dns := installFakeTXT(t)
	base := "/app/org/org-acme/settings/sso"

	// Anonymous: bounced to sign-in, coming back here.
	anon := oidctest.NewBrowser(t)
	resp, err := anon.Get(h.app.URL + base)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/login?return_to="+url.QueryEscape(base) {
		t.Fatalf("anonymous: %d %q", resp.StatusCode, loc)
	}

	// Bob (no org.sso) is refused the page and the posts.
	bobB := oidctest.NewBrowser(t)
	_, bobCSRF := h.signedIn(bobB, "u-bob")
	if status, _, _ := h.get(bobB, base); status != http.StatusForbidden {
		t.Errorf("member page: %d", status)
	}
	if resp := h.postForm(bobB, base+"/domains", bobCSRF, url.Values{"domain": {"bob.example"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("member add: %d", resp.StatusCode)
	}
	// Org B's owner gets nothing from org A.
	adminB := oidctest.NewBrowser(t)
	h.signedIn(adminB, "u-admin")
	if status, _, _ := h.get(adminB, base); status != http.StatusForbidden {
		t.Errorf("other org page: %d", status)
	}

	b := oidctest.NewBrowser(t)
	_, csrf := h.signedIn(b, "u-alice")
	status, _, body := h.get(b, "/app/org/org-acme/settings")
	if status != http.StatusOK || !strings.Contains(body, `href="`+base+`"`) {
		t.Fatalf("org settings has no SSO tab: %d", status)
	}
	status, _, body = h.get(b, base)
	if status != http.StatusOK || !strings.Contains(body, "Email domains") || !strings.Contains(body, "No domains yet") {
		t.Fatalf("page: %d", status)
	}
	// Missing CSRF token is refused by the global middleware.
	if resp := h.postForm(b, base+"/domains", "", url.Values{"domain": {"x.example"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("add without CSRF: %d", resp.StatusCode)
	}
	resp = h.postForm(b, base+"/domains", csrf, url.Values{"domain": {"Acme.Example"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != base+"?notice=added" {
		t.Fatalf("add: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	var id, token string
	if err := h.db.QueryRow(`SELECT id, verify_token FROM org_domains WHERE org_id='org-acme' AND domain='acme.example'`).Scan(&id, &token); err != nil {
		t.Fatal(err)
	}
	_, _, body = h.get(b, base+"?notice=added")
	for _, want := range []string{"Domain added.", "_boardchestrator-challenge.acme.example", "bc-verify=" + token, "Pending verification", base + "/domains/" + id + "/verify"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	resp = h.postForm(b, base+"/domains/"+id+"/verify", csrf, nil)
	if resp.Header.Get("Location") != base+"?error=record_missing" {
		t.Fatalf("verify without record: %q", resp.Header.Get("Location"))
	}
	_, _, body = h.get(b, base+"?error=record_missing")
	if !strings.Contains(body, "We couldn&#39;t find the TXT record") && !strings.Contains(body, "We couldn't find the TXT record") {
		t.Error("no record-missing copy")
	}
	dns.set("_boardchestrator-challenge.acme.example", "bc-verify="+token)
	resp = h.postForm(b, base+"/domains/"+id+"/verify", csrf, nil)
	if resp.Header.Get("Location") != base+"?notice=verified" {
		t.Fatalf("verify: %q", resp.Header.Get("Location"))
	}
	_, _, body = h.get(b, base)
	if !strings.Contains(body, ">Verified<") || strings.Contains(body, "bc-verify=") {
		t.Error("verified domain not shown as verified")
	}
	resp = h.postForm(b, base+"/domains", csrf, url.Values{"domain": {"192.0.2.1"}})
	if resp.Header.Get("Location") != base+"?error=ip" {
		t.Errorf("IP add: %q", resp.Header.Get("Location"))
	}
	// Unknown codes echo nothing.
	if _, _, body := h.get(b, base+"?error=%3Cscript%3E"); strings.Contains(body, "<script>") || strings.Contains(body, "bc-alert-error") {
		t.Error("unknown error code rendered")
	}
	resp = h.postForm(b, base+"/domains/"+id+"/remove", csrf, nil)
	if resp.Header.Get("Location") != base+"?notice=removed" || h.n(`SELECT COUNT(*) FROM org_domains`) != 0 {
		t.Fatalf("remove: %q", resp.Header.Get("Location"))
	}
}

// ssoProvider adds an org-owned OIDC provider row for orgID backed by idp
// and makes the registry reload.
func (h *smHarness) ssoProvider(id, orgID string, idp *oidctest.Server, enabled bool) {
	h.t.Helper()
	enc, err := tenant.Encrypt(tenant.PadKey(testConfig().SecretKey), idp.ClientSecret)
	if err != nil {
		h.t.Fatal(err)
	}
	en := 0
	if enabled {
		en = 1
	}
	if _, err := h.db.Exec(`INSERT INTO auth_providers (id, org_id, kind, preset, display_name, enabled, managed_by,
		issuer, client_id, client_secret_enc) VALUES (?, ?, 'oidc', 'generic', ?, ?, 'ui', ?, ?, ?)`,
		id, orgID, "SSO "+id, en, idp.Issuer(), idp.ClientID, enc); err != nil {
		h.t.Fatal(err)
	}
	h.srv.IdP().Invalidate()
}

func (h *smHarness) verifiedDomain(orgID, domain string, verified bool) {
	h.t.Helper()
	var at any
	if verified {
		at = "2026-10-01T00:00:00.000Z"
	}
	if _, err := h.db.Exec(`INSERT INTO org_domains (id, org_id, domain, verify_token, verified_at, created_at)
		VALUES (?, ?, ?, 'tok', ?, '2026-10-01T00:00:00.000Z')`, "d-"+orgID+"-"+domain, orgID, domain, at); err != nil {
		h.t.Fatal(err)
	}
}

func TestHomeRealmDiscovery(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	seedSSOOrgs(t, h)
	acmeIdP := oidctest.New(t)
	h.verifiedDomain("org-acme", "corp.example", true)
	h.verifiedDomain("org-acme", "xn--bcher-kva.example", true)
	h.verifiedDomain("org-acme", "pending.example", false)
	h.verifiedDomain("org-b", "beta.example", true) // org B: verified, no provider
	h.verifiedDomain("org-b", "off.example", true)

	// Before any org provider exists the SSO box is not offered.
	b := oidctest.NewBrowser(t)
	if _, _, body := h.get(b, "/login"); strings.Contains(body, "Sign in with SSO") {
		t.Error("SSO box shown with no org providers")
	}
	h.ssoProvider("acme-sso", "org-acme", acmeIdP, true)
	h.ssoProvider("beta-off", "org-b", oidctest.New(t), false)

	_, _, body := h.get(b, "/login?return_to=/app/x")
	if !strings.Contains(body, "Sign in with SSO") || !strings.Contains(body, `action="/auth/sso/discover"`) ||
		!strings.Contains(body, `name="return_to" value="/app/x"`) {
		t.Fatal("no SSO box on /login")
	}
	if strings.Contains(body, "/auth/acme-sso") {
		t.Error("org-owned provider listed as a /login button")
	}

	// Hit: redirect to the org's provider with login_hint and return_to.
	email := "Carol@Corp.Example"
	resp, err := b.Get(h.app.URL + "/auth/sso/discover?email=" + url.QueryEscape(email) + "&return_to=" + url.QueryEscape("/app/x"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || loc == nil || loc.Path != "/auth/acme-sso" ||
		loc.Query().Get("login_hint") != email || loc.Query().Get("return_to") != "/app/x" {
		t.Fatalf("discover: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Followed through, the IdP's authorize endpoint receives the hint.
	steps, err := b.Follow(h.app.URL+loc.String(), 8, func(next *url.URL) bool {
		return strings.HasSuffix(next.Path, "/callback")
	})
	if err != nil {
		t.Fatalf("follow: %v %+v", err, steps)
	}
	ars := acmeIdP.AuthorizeRequests()
	if len(ars) != 1 || ars[0].LoginHint != email {
		t.Fatalf("authorize requests %+v", ars)
	}
	// IDN email domains are matched by their punycode form.
	resp, _ = b.Get(h.app.URL + "/auth/sso/discover?email=" + url.QueryEscape("ann@bücher.example"))
	_ = resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Location"), "/auth/acme-sso?") {
		t.Errorf("IDN discover: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// A dangerous return_to is dropped, not carried.
	resp, _ = b.Get(h.app.URL + "/auth/sso/discover?email=carol%40corp.example&return_to=" + url.QueryEscape("//evil.example"))
	_ = resp.Body.Close()
	if l, _ := url.Parse(resp.Header.Get("Location")); l == nil || l.Query().Has("return_to") {
		t.Errorf("open redirect carried: %q", resp.Header.Get("Location"))
	}

	// Misses all look the same: unknown, pending, verified without a
	// provider, verified with only a disabled provider, malformed, the
	// parent of a verified subdomain's sibling.
	const marker = "MISS-ADDRESS"
	var first string
	for _, e := range []string{"x@unknown.example", "x@pending.example", "x@beta.example", "x@off.example",
		"not-an-email", "x@sub.corp.example", "x@com", ""} {
		status, _, body := h.get(b, "/auth/sso/discover?email="+url.QueryEscape(e))
		if status != http.StatusOK {
			t.Fatalf("miss %q: %d", e, status)
		}
		if !strings.Contains(body, "couldn&#39;t find single sign-on for that address") && !strings.Contains(body, "couldn't find single sign-on for that address") {
			t.Fatalf("miss %q: no neutral message", e)
		}
		if e != "" {
			body = strings.ReplaceAll(body, `value="`+e+`"`, `value="`+marker+`"`)
		} else {
			body = strings.Replace(body, `name="email" value=""`, `name="email" value="`+marker+`"`, 1)
		}
		if first == "" {
			first = body
		} else if body != first {
			t.Errorf("miss %q renders differently from the first miss", e)
		}
	}
	if n := len(acmeIdP.AuthorizeRequests()); n != 1 {
		t.Errorf("misses reached the IdP: %d authorize requests", n)
	}
}

func TestHomeRealmDiscoveryRateLimited(t *testing.T) {
	h := newSMHarness(t, smOpts{defaultRateLimit: true})
	b := oidctest.NewBrowser(t)
	for i := range 10 {
		if status, _, _ := h.get(b, "/auth/sso/discover?email=x%40unknown.example"); status != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, status)
		}
	}
	status, hdr, _ := h.get(b, "/auth/sso/discover?email=x%40unknown.example")
	if status != http.StatusTooManyRequests || hdr.Get("Retry-After") == "" {
		t.Fatalf("11th discover: %d %q", status, hdr.Get("Retry-After"))
	}
}

// postForm posts form (plus the CSRF field when csrf is set) without
// following redirects.
func (h *smHarness) postForm(b *oidctest.Browser, path, csrf string, form url.Values) *http.Response {
	h.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if csrf != "" {
		form.Set("csrf_token", csrf)
	}
	req, _ := http.NewRequest(http.MethodPost, h.app.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

// refused reports a dispatch refusal: scope or permission.
func refused(err error) bool {
	return errors.Is(err, action.ErrForbidden) || errors.Is(err, action.ErrScope)
}
