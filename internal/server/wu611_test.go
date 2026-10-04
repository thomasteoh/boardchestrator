package server_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/config"
)

// WU-611: SCIM 2.0 provisioning (SPEC §7.8) end to end through the
// production server wiring: tokens by action, /scim/v2 with Entra- and
// Okta-shaped request sequences, org isolation, deprovisioning, group
// mapping, and the sign-in interplay (Q14).

type scimResp struct {
	status int
	hdr    http.Header
	body   map[string]any
	raw    string
}

// scimToken creates a SCIM token in org as actor and returns the plaintext.
func scimToken(t *testing.T, d *action.Dispatcher, actor action.Actor, org string) (string, action.SCIMTokenCreated) {
	t.Helper()
	out, err := call(d, actor, org, action.ActionSCIMTokenCreate, map[string]any{"name": "IdP " + org})
	if err != nil {
		t.Fatalf("scim.token.create: %v", err)
	}
	c, ok := out.(action.SCIMTokenCreated)
	if !ok || c.Token == "" {
		t.Fatalf("scim.token.create result %#v", out)
	}
	return c.Token, c
}

func (h *smHarness) scim(token, method, path string, body any) scimResp {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, h.app.URL+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := scimResp{status: resp.StatusCode, hdr: resp.Header, raw: string(raw)}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.body); err != nil {
			h.t.Fatalf("%s %s: non-JSON body %q", method, path, raw)
		}
	}
	return out
}

func (r scimResp) str(k string) string { s, _ := r.body[k].(string); return s }

func (r scimResp) total() int {
	n, _ := r.body["totalResults"].(float64)
	return int(n)
}

// expectSCIM asserts the status and, for errors, the RFC 7644 envelope.
func expectSCIM(t *testing.T, step string, r scimResp, status int, scimType string) {
	t.Helper()
	if r.status != status {
		t.Fatalf("%s: status %d, want %d: %s", step, r.status, status, r.raw)
	}
	if status == http.StatusNoContent {
		return
	}
	if ct := r.hdr.Get("Content-Type"); ct != "application/scim+json" {
		t.Errorf("%s: Content-Type %q", step, ct)
	}
	if status >= 400 {
		schemas, _ := r.body["schemas"].([]any)
		if len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" ||
			r.str("status") != strconv.Itoa(status) || r.str("detail") == "" {
			t.Errorf("%s: error envelope %s", step, r.raw)
		}
		if scimType != "" && r.str("scimType") != scimType {
			t.Errorf("%s: scimType %q, want %q", step, r.str("scimType"), scimType)
		}
	}
}

func usersPath(filter string, extra ...string) string {
	q := url.Values{"filter": {filter}}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	return "/scim/v2/Users?" + q.Encode()
}

// wu611Setup is wu608Setup plus SCIM tokens for org-acme (alice) and org-b
// (admin) and a mapping of the SCIM group "Engineers" to Team Admin on
// t-ops and "Ops" to Viewer on p-web, both for all providers.
func wu611Setup(t *testing.T, o smOpts) (*smHarness, *oidctest.Server, *action.Dispatcher, string, string) {
	h, acme, _, d := wu608Setup(t, o)
	alice := user("u-alice", "")
	tokA, _ := scimToken(t, d, alice, "org-acme")
	tokB, _ := scimToken(t, d, user("u-admin", ""), "org-b")
	for _, m := range []map[string]string{
		{"group_value": "Engineers", "role_id": roleTeamAdmin, "resource_type": "team", "resource_id": "t-ops"},
		{"group_value": "Ops", "role_id": roleViewerSys, "resource_type": "project", "resource_id": "p-web"},
	} {
		if _, err := call(d, alice, "org-acme", action.ActionIdPMappingCreate, m); err != nil {
			t.Fatal(err)
		}
	}
	return h, acme, d, tokA, tokB
}

func TestSCIMTokenActions(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	d, rec := orgDispatcher(h)
	alice := user("u-alice", "")

	raw, _ := json.Marshal(map[string]any{"name": "Entra", "expires_in_days": 30})
	out, err := d.Dispatch(t.Context(), alice, action.ActionSCIMTokenCreate, raw, action.Opts{Org: "org-acme", Idem: "idem-scim-1"})
	if err != nil {
		t.Fatal(err)
	}
	created := out.(action.SCIMTokenCreated)
	prefix, ok := action.ParseSCIMToken(created.Token)
	if !ok || prefix != created.Prefix || !strings.HasPrefix(created.Token, "bcscim_"+prefix+"_") || created.ExpiresAt == "" {
		t.Fatalf("token %+v", created)
	}
	secret := strings.TrimPrefix(created.Token, "bcscim_"+prefix+"_")
	// Stored as a hash, never in plaintext.
	if h.n(`SELECT COUNT(*) FROM scim_tokens WHERE token_hash=? AND org_id='org-acme'`, action.SCIMTokenHash(created.Token)) != 1 {
		t.Error("token hash not stored")
	}
	// The plaintext never reaches audit, events or idempotency storage.
	for _, q := range []string{
		`SELECT COUNT(*) FROM audit_log WHERE detail_json LIKE '%'||?||'%'`,
		`SELECT COUNT(*) FROM idempotency_keys WHERE result_json LIKE '%'||?||'%'`,
		`SELECT COUNT(*) FROM scim_tokens WHERE token_hash LIKE '%'||?||'%' OR name LIKE '%'||?||'%'`,
	} {
		args := []any{secret}
		if strings.Count(q, "?") == 2 {
			args = append(args, secret)
		}
		if n := h.n(q, args...); n != 0 {
			t.Errorf("secret found: %s", q)
		}
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='scim.token.create' AND org_id='org-acme'`) != 1 {
		t.Error("create not audited")
	}
	if h.n(`SELECT COUNT(*) FROM idempotency_keys WHERE key='idem-scim-1'`) != 1 {
		t.Error("idempotency row missing (the redaction check above would be vacuous)")
	}
	evs := rec.all()
	if len(evs) == 0 {
		t.Fatal("no events recorded")
	}
	for _, ev := range evs {
		if strings.Contains(string(ev.Payload), secret) || strings.Contains(ev.Subject, secret) {
			t.Errorf("event %s carries the token", ev.Name)
		}
	}
	// An idempotent replay returns the redacted form.
	again, err := d.Dispatch(t.Context(), alice, action.ActionSCIMTokenCreate, raw, action.Opts{Org: "org-acme", Idem: "idem-scim-1"})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(again); strings.Contains(string(b), secret) {
		t.Error("idempotent replay returned the token")
	}

	// list: no secrets, status.
	lout, err := call(d, alice, "org-acme", action.ActionSCIMTokenList, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := json.Marshal(lout)
	if strings.Contains(string(lb), secret) || strings.Contains(string(lb), "hash") || !strings.Contains(string(lb), `"status":"active"`) {
		t.Errorf("list %s", lb)
	}

	// Permission: a member without org.sso, another org's owner, an agent.
	if _, err := call(d, user("u-bob", ""), "org-acme", action.ActionSCIMTokenCreate, map[string]any{"name": "x"}); err == nil {
		t.Error("member without org.sso created a token")
	}
	if _, err := call(d, user("u-admin", ""), "org-acme", action.ActionSCIMTokenList, map[string]any{}); err == nil {
		t.Error("other org's owner listed tokens")
	}
	if _, err := call(d, alice, "org-acme", action.ActionSCIMTokenCreate, map[string]any{"name": ""}); err == nil {
		t.Error("empty name accepted")
	}
	if _, err := call(d, alice, "org-acme", action.ActionSCIMTokenCreate, map[string]any{"name": "x", "expires_in_days": 5000}); err == nil {
		t.Error("expiry 5000 days accepted")
	}

	// Revoke: then the token is refused; revoking twice or another org's
	// token is not found.
	if r := h.scim(created.Token, http.MethodGet, "/scim/v2/Users", nil); r.status != http.StatusOK {
		t.Fatalf("token before revoke: %d", r.status)
	}
	if _, err := call(d, user("u-admin", ""), "org-b", action.ActionSCIMTokenRevoke, map[string]any{"id": created.ID}); err == nil {
		t.Error("org-b revoked org-acme's token")
	}
	if _, err := call(d, alice, "org-acme", action.ActionSCIMTokenRevoke, map[string]any{"id": created.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(d, alice, "org-acme", action.ActionSCIMTokenRevoke, map[string]any{"id": created.ID}); err == nil {
		t.Error("double revoke succeeded")
	}
	expectSCIM(t, "revoked", h.scim(created.Token, http.MethodGet, "/scim/v2/Users", nil), http.StatusUnauthorized, "")
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='scim.token.revoke' AND org_id='org-acme'`) != 1 {
		t.Error("revoke not audited")
	}
}

func TestSCIMAuthentication(t *testing.T) {
	h, _, _, d := wu608Setup(t, smOpts{})
	tok, c := scimToken(t, d, user("u-alice", ""), "org-acme")
	prefix := c.Prefix
	wrongSecret := "bcscim_" + prefix + "_" + strings.Repeat("0", 64)
	h.exec(`INSERT INTO scim_tokens (id, org_id, name, prefix, token_hash, expires_at) VALUES ('t-exp','org-acme','old','aaaaaaaaaaaa',?, '2020-01-01T00:00:00.000Z')`,
		action.SCIMTokenHash("bcscim_aaaaaaaaaaaa_"+strings.Repeat("1", 64)))
	expired := "bcscim_aaaaaaaaaaaa_" + strings.Repeat("1", 64)
	for name, token := range map[string]string{
		"missing":      "",
		"malformed":    "not-a-token",
		"wrong secret": wrongSecret,
		"expired":      expired,
		"api key":      "deadbeef" + strings.Repeat("ab", 32),
		"uppercase":    strings.ToUpper(tok),
	} {
		r := h.scim(token, http.MethodGet, "/scim/v2/Users", nil)
		expectSCIM(t, name, r, http.StatusUnauthorized, "")
		if r.hdr.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: no WWW-Authenticate", name)
		}
	}
	// A session cookie is not a SCIM credential, and the route needs no CSRF.
	req, _ := http.NewRequest(http.MethodPost, h.app.URL+"/scim/v2/Users", strings.NewReader(`{}`))
	raw, _, _ := h.newSession("u-alice")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: raw})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("session cookie on SCIM: %d", resp.StatusCode)
	}
	// The valid token works with a lower-case scheme and touches last_used_at.
	req, _ = http.NewRequest(http.MethodGet, h.app.URL+"/scim/v2/ServiceProviderConfig", nil)
	req.Header.Set("Authorization", "bearer "+tok)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid token: %d", resp.StatusCode)
	}
	if h.n(`SELECT COUNT(*) FROM scim_tokens WHERE id=? AND last_used_at IS NOT NULL`, c.ID) != 1 {
		t.Error("last_used_at not set")
	}
	// Unknown endpoint under /scim/v2 is a SCIM 404.
	expectSCIM(t, "unknown endpoint", h.scim(tok, http.MethodGet, "/scim/v2/Nope", nil), http.StatusNotFound, "")
}

func (h *smHarness) newSession(userID string) (raw, csrf string, err error) {
	raw, sess, err := auth.NewSessionStore(h.db).Create(h.t.Context(), userID, "", "")
	if err != nil {
		return "", "", err
	}
	return raw, auth.CSRFToken(smSessionSecret, sess.TokenHash), nil
}

func TestSCIMDiscoveryEndpoints(t *testing.T) {
	h, _, _, d := wu608Setup(t, smOpts{})
	tok, _ := scimToken(t, d, user("u-alice", ""), "org-acme")
	r := h.scim(tok, http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
	expectSCIM(t, "spc", r, http.StatusOK, "")
	feature := func(name string) map[string]any { m, _ := r.body[name].(map[string]any); return m }
	if feature("patch")["supported"] != true || feature("filter")["supported"] != true || feature("filter")["maxResults"] != float64(200) {
		t.Errorf("spc %s", r.raw)
	}
	for _, f := range []string{"bulk", "sort", "etag", "changePassword"} {
		if feature(f)["supported"] != false {
			t.Errorf("%s supported: %s", f, r.raw)
		}
	}
	r = h.scim(tok, http.MethodGet, "/scim/v2/ResourceTypes", nil)
	expectSCIM(t, "resource types", r, http.StatusOK, "")
	if r.total() != 2 || !strings.Contains(r.raw, `"endpoint":"/Users"`) || !strings.Contains(r.raw, `"endpoint":"/Groups"`) {
		t.Errorf("resource types %s", r.raw)
	}
	r = h.scim(tok, http.MethodGet, "/scim/v2/Schemas", nil)
	if r.total() != 2 || !strings.Contains(r.raw, "urn:ietf:params:scim:schemas:core:2.0:User") {
		t.Errorf("schemas %s", r.raw)
	}
	expectSCIM(t, "schema by id", h.scim(tok, http.MethodGet, "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group", nil), http.StatusOK, "")
	expectSCIM(t, "resource type 404", h.scim(tok, http.MethodGet, "/scim/v2/ResourceTypes/Nope", nil), http.StatusNotFound, "")
}

// The Entra ID provisioning sequence, as recorded from its request shapes.
func TestSCIMEntraSequence(t *testing.T) {
	h, _, _, tok, _ := wu611Setup(t, smOpts{})
	// Carol has an org-b membership too, so her sessions survive
	// deactivation in org-acme; she also has API keys in both orgs.
	// Startup probe: a random GUID userName returns an empty list.
	r := h.scim(tok, http.MethodGet, usersPath(`userName eq "8f1c2c9e-0d55-4f0c-a0a5-3c1b3c4c6b1e"`), nil)
	expectSCIM(t, "probe", r, http.StatusOK, "")
	if r.total() != 0 || !strings.Contains(r.raw, `"Resources":[]`) || !strings.Contains(r.raw, "ListResponse") {
		t.Fatalf("probe %s", r.raw)
	}
	r = h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"},
		"externalId":  "carol-object-id",
		"userName":    "Carol@corp.example",
		"active":      true,
		"displayName": "Carol Jones",
		"emails":      []map[string]any{{"primary": true, "type": "work", "value": "carol@corp.example"}},
		"name":        map[string]any{"formatted": "Carol Jones", "familyName": "Jones", "givenName": "Carol"},
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{"department": "Engineering", "manager": map[string]any{"value": "x"}},
		"title":     "Engineer",
		"addresses": []map[string]any{{"type": "work", "country": "AU"}},
	})
	expectSCIM(t, "create", r, http.StatusCreated, "")
	carol := r.str("id")
	loc := r.hdr.Get("Location")
	if carol == "" || !strings.HasSuffix(loc, "/scim/v2/Users/"+carol) || r.body["active"] != true {
		t.Fatalf("create %s (Location %q)", r.raw, loc)
	}
	m, _ := r.body["meta"].(map[string]any)
	if m["resourceType"] != "User" || m["location"] != loc || m["created"] == "" || m["lastModified"] == "" {
		t.Errorf("meta %v", m)
	}
	var carolUser string
	if err := h.db.QueryRow(`SELECT user_id FROM scim_users WHERE id=? AND org_id='org-acme'`, carol).Scan(&carolUser); err != nil {
		t.Fatal(err)
	}
	if h.n(`SELECT COUNT(*) FROM users WHERE id=? AND email='carol@corp.example' AND name='Carol Jones'`, carolUser) != 1 {
		t.Error("platform user not created")
	}
	if got := h.membership("org-acme", carolUser, "org", "org-acme"); got != roleMemberSys+"/scim" {
		t.Errorf("membership %q, want Member/scim", got)
	}
	// Filters Entra uses: userName (case-insensitive), externalId.
	for _, f := range []string{`userName eq "carol@corp.example"`, `externalId eq "carol-object-id"`, `emails[type eq "work"].value eq "carol@corp.example"`} {
		if r := h.scim(tok, http.MethodGet, usersPath(f), nil); r.total() != 1 {
			t.Errorf("filter %s: %s", f, r.raw)
		}
	}
	// Attribute updates: capitalised ops, paths, value-path emails,
	// enterprise extension ignored.
	r = h.scim(tok, http.MethodPatch, "/scim/v2/Users/"+carol, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "Replace", "path": "displayName", "value": "Carol J"},
			{"op": "Replace", "path": "name.givenName", "value": "Caz"},
			{"op": "Replace", "path": `emails[type eq "work"].value`, "value": "carol.j@corp.example"},
			{"op": "Add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "Ops"},
			{"op": "Replace", "path": "title", "value": "Lead"},
		},
	})
	expectSCIM(t, "patch attrs", r, http.StatusOK, "")
	if r.str("displayName") != "Carol J" || !strings.Contains(r.raw, `"givenName":"Caz"`) || !strings.Contains(r.raw, "carol.j@corp.example") {
		t.Errorf("patched %s", r.raw)
	}
	// SCIM never changes the platform account's email.
	if h.n(`SELECT COUNT(*) FROM users WHERE id=? AND email='carol@corp.example'`, carolUser) != 1 {
		t.Error("platform email changed by SCIM")
	}

	// Group created empty, then members added (Entra adds members by PATCH).
	r = h.scim(tok, http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "externalId": "grp-eng", "displayName": "Engineers", "members": []any{},
	})
	expectSCIM(t, "group create", r, http.StatusCreated, "")
	eng := r.str("id")
	if r := h.scim(tok, http.MethodGet, "/scim/v2/Groups?"+url.Values{"filter": {`displayName eq "Engineers"`}, "excludedAttributes": {"members"}}.Encode(), nil); r.total() != 1 || strings.Contains(r.raw, `"members"`) {
		t.Errorf("group filter %s", r.raw)
	}
	r = h.scim(tok, http.MethodPatch, "/scim/v2/Groups/"+eng, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "Add", "path": "members", "value": []map[string]any{{"value": carol}}}},
	})
	expectSCIM(t, "add member", r, http.StatusOK, "")
	if got := h.membership("org-acme", carolUser, "team", "t-ops"); got != roleTeamAdmin+"/idp" {
		t.Errorf("after add: team %q, want Team Admin/idp", got)
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='membership.synced' AND actor_type='service' AND actor_id LIKE 'scim:%' AND org_id='org-acme'`) != 1 {
		t.Error("membership.synced not audited as the SCIM actor")
	}
	// Entra removes members with a value list.
	r = h.scim(tok, http.MethodPatch, "/scim/v2/Groups/"+eng, map[string]any{
		"Operations": []map[string]any{{"op": "Remove", "path": "members", "value": []map[string]any{{"value": carol}}}},
	})
	expectSCIM(t, "remove member", r, http.StatusOK, "")
	if got := h.membership("org-acme", carolUser, "team", "t-ops"); got != "" {
		t.Errorf("after remove: team %q", got)
	}
	h.scim(tok, http.MethodPatch, "/scim/v2/Groups/"+eng, map[string]any{
		"Operations": []map[string]any{{"op": "Add", "path": "members", "value": []map[string]any{{"value": carol}}}},
	})

	// API keys in both orgs, a session, and an org-b membership.
	h.exec(`INSERT INTO api_keys (id, user_id, org_id, name, prefix, hash) VALUES ('k-a',?,'org-acme','a','11111111','h'), ('k-b',?,'org-b','b','22222222','h')`, carolUser, carolUser)
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES ('m-carol-b','org-b',?,'user','org','org-b',?)`, carolUser, roleViewerSys)
	if _, _, err := h.newSession(carolUser); err != nil {
		t.Fatal(err)
	}

	// Deactivate with Entra's string boolean.
	r = h.scim(tok, http.MethodPatch, "/scim/v2/Users/"+carol, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "Replace", "path": "active", "value": "False"}},
	})
	expectSCIM(t, "deactivate", r, http.StatusOK, "")
	if r.body["active"] != false {
		t.Errorf("active after deactivate %s", r.raw)
	}
	if n := h.n(`SELECT COUNT(*) FROM memberships WHERE org_id='org-acme' AND actor_id=?`, carolUser); n != 0 {
		t.Errorf("%d org-acme memberships remain", n)
	}
	if h.n(`SELECT COUNT(*) FROM api_keys WHERE id='k-a' AND revoked_at IS NOT NULL`) != 1 ||
		h.n(`SELECT COUNT(*) FROM api_keys WHERE id='k-b' AND revoked_at IS NULL`) != 1 {
		t.Error("API keys: org-acme key must be revoked, org-b key kept")
	}
	if h.n(`SELECT COUNT(*) FROM memberships WHERE id='m-carol-b'`) != 1 || h.n(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, carolUser) != 1 {
		t.Error("org-b membership or session touched (she still belongs to org-b)")
	}
	for _, a := range []string{"scim.user.deactivated", "membership.scim_removed", "apikey.scim_revoked"} {
		if h.n(`SELECT COUNT(*) FROM audit_log WHERE action=? AND org_id='org-acme' AND actor_type='service' AND subject=?`, a, carolUser) != 1 {
			t.Errorf("audit %s missing", a)
		}
	}
	// Group changes while inactive grant nothing.
	h.scim(tok, http.MethodPatch, "/scim/v2/Groups/"+eng, map[string]any{
		"Operations": []map[string]any{{"op": "Replace", "path": "displayName", "value": "Engineers"}},
	})
	if h.n(`SELECT COUNT(*) FROM memberships WHERE org_id='org-acme' AND actor_id=?`, carolUser) != 0 {
		t.Error("inactive user regained memberships")
	}

	// Reactivate (no-path object form, capitalised op): the SCIM membership
	// and the group-mapped one come back.
	r = h.scim(tok, http.MethodPatch, "/scim/v2/Users/"+carol, map[string]any{
		"Operations": []map[string]any{{"op": "Replace", "value": map[string]any{"active": "True", "name.familyName": "Jones-Smith"}}},
	})
	expectSCIM(t, "reactivate", r, http.StatusOK, "")
	if got := h.membership("org-acme", carolUser, "org", "org-acme"); got != roleMemberSys+"/scim" {
		t.Errorf("reactivated org membership %q", got)
	}
	if got := h.membership("org-acme", carolUser, "team", "t-ops"); got != roleTeamAdmin+"/idp" {
		t.Errorf("reactivated team membership %q", got)
	}
	if !strings.Contains(r.raw, "Jones-Smith") {
		t.Errorf("no-path name.familyName not applied: %s", r.raw)
	}

	// Delete the user: memberships go, the platform user stays.
	expectSCIM(t, "delete user", h.scim(tok, http.MethodDelete, "/scim/v2/Users/"+carol, nil), http.StatusNoContent, "")
	if h.n(`SELECT COUNT(*) FROM memberships WHERE org_id='org-acme' AND actor_id=?`, carolUser) != 0 ||
		h.n(`SELECT COUNT(*) FROM scim_users WHERE id=?`, carol) != 0 ||
		h.n(`SELECT COUNT(*) FROM scim_group_members WHERE user_id=?`, carolUser) != 0 {
		t.Error("delete left memberships or SCIM rows")
	}
	if h.n(`SELECT COUNT(*) FROM users WHERE id=? AND deleted_at IS NULL`, carolUser) != 1 {
		t.Error("platform user deleted")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='scim.user.deleted' AND subject=?`, carolUser) != 1 {
		t.Error("delete not audited")
	}
	expectSCIM(t, "get deleted", h.scim(tok, http.MethodGet, "/scim/v2/Users/"+carol, nil), http.StatusNotFound, "")
	// Removing a member that no longer exists is a no-op.
	expectSCIM(t, "remove gone member", h.scim(tok, http.MethodPatch, "/scim/v2/Groups/"+eng, map[string]any{
		"Operations": []map[string]any{{"op": "Remove", "path": "members", "value": []map[string]any{{"value": carol}}}},
	}), http.StatusOK, "")
	expectSCIM(t, "delete group", h.scim(tok, http.MethodDelete, "/scim/v2/Groups/"+eng, nil), http.StatusNoContent, "")
	expectSCIM(t, "get deleted group", h.scim(tok, http.MethodGet, "/scim/v2/Groups/"+eng, nil), http.StatusNotFound, "")
}

// The Okta provisioning sequence: PUT for user updates, filtered list with
// startIndex/count, group members by PATCH replace and value-filter remove.
func TestSCIMOktaSequence(t *testing.T) {
	h, _, _, tok, _ := wu611Setup(t, smOpts{})
	r := h.scim(tok, http.MethodGet, usersPath(`userName eq "dave@corp.example"`, "startIndex", "1", "count", "100"), nil)
	expectSCIM(t, "lookup", r, http.StatusOK, "")
	if r.total() != 0 {
		t.Fatalf("lookup %s", r.raw)
	}
	daveRes := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "dave@corp.example",
		"name":        map[string]any{"givenName": "Dave", "familyName": "Lee"},
		"emails":      []map[string]any{{"primary": true, "value": "dave@corp.example", "type": "work"}},
		"displayName": "Dave Lee", "locale": "en-AU", "externalId": "00u1", "groups": []any{},
		"password": "ignored", "active": true,
	}
	r = h.scim(tok, http.MethodPost, "/scim/v2/Users", daveRes)
	expectSCIM(t, "create", r, http.StatusCreated, "")
	dave := r.str("id")
	var daveUser string
	if err := h.db.QueryRow(`SELECT user_id FROM scim_users WHERE id=?`, dave).Scan(&daveUser); err != nil {
		t.Fatal(err)
	}
	// Duplicate userName: 409 uniqueness.
	expectSCIM(t, "duplicate", h.scim(tok, http.MethodPost, "/scim/v2/Users", daveRes), http.StatusConflict, "uniqueness")
	// Okta updates by PUT: a full replacement; active false deactivates.
	daveRes["id"] = dave
	daveRes["name"] = map[string]any{"givenName": "David", "familyName": "Lee"}
	daveRes["active"] = false
	r = h.scim(tok, http.MethodPut, "/scim/v2/Users/"+dave, daveRes)
	expectSCIM(t, "put deactivate", r, http.StatusOK, "")
	if !strings.Contains(r.raw, `"givenName":"David"`) || r.body["active"] != false {
		t.Errorf("put %s", r.raw)
	}
	if h.membership("org-acme", daveUser, "org", "org-acme") != "" {
		t.Error("PUT active=false kept the membership")
	}
	// Dave belongs nowhere else, so his sessions are revoked.
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='session.scim_revoked' AND subject=?`, daveUser) != 1 {
		t.Error("sessions of a user with no memberships left not revoked")
	}
	daveRes["active"] = true
	expectSCIM(t, "put reactivate", h.scim(tok, http.MethodPut, "/scim/v2/Users/"+dave, daveRes), http.StatusOK, "")
	if h.membership("org-acme", daveUser, "org", "org-acme") != roleMemberSys+"/scim" {
		t.Error("PUT active=true did not restore the membership")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='scim.user.reactivated' AND subject=?`, daveUser) != 1 {
		t.Error("reactivation not audited")
	}
	// Okta creates groups with members.
	r = h.scim(tok, http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": "Engineers",
		"members": []map[string]any{{"value": dave, "display": "dave@corp.example"}},
	})
	expectSCIM(t, "group create", r, http.StatusCreated, "")
	grp := r.str("id")
	if !strings.Contains(r.raw, `"value":"`+dave+`"`) {
		t.Errorf("group members %s", r.raw)
	}
	if h.membership("org-acme", daveUser, "team", "t-ops") != roleTeamAdmin+"/idp" {
		t.Error("group create did not map the role")
	}
	// Okta renames by PATCH replace without a path; "Ops" maps to p-web and
	// "Engineers" no longer applies.
	r = h.scim(tok, http.MethodPatch, "/scim/v2/Groups/"+grp, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "value": map[string]any{"id": grp, "displayName": "Ops"}}},
	})
	expectSCIM(t, "rename", r, http.StatusOK, "")
	if h.membership("org-acme", daveUser, "team", "t-ops") != "" || h.membership("org-acme", daveUser, "project", "p-web") != roleViewerSys+"/idp" {
		t.Errorf("after rename: team %q project %q", h.membership("org-acme", daveUser, "team", "t-ops"), h.membership("org-acme", daveUser, "project", "p-web"))
	}
	// Okta removes one member with a value filter.
	r = h.scim(tok, http.MethodPatch, "/scim/v2/Groups/"+grp, map[string]any{
		"Operations": []map[string]any{{"op": "remove", "path": `members[value eq "` + dave + `"]`}},
	})
	expectSCIM(t, "remove by filter", r, http.StatusOK, "")
	if h.membership("org-acme", daveUser, "project", "p-web") != "" || strings.Contains(r.raw, dave) {
		t.Errorf("remove by filter %s", r.raw)
	}
	// ... and replaces the member list.
	r = h.scim(tok, http.MethodPatch, "/scim/v2/Groups/"+grp, map[string]any{
		"Operations": []map[string]any{{"op": "replace", "path": "members", "value": []map[string]any{{"value": dave}}}},
	})
	expectSCIM(t, "replace members", r, http.StatusOK, "")
	if h.membership("org-acme", daveUser, "project", "p-web") != roleViewerSys+"/idp" {
		t.Error("members replace did not map the role")
	}
	if r := h.scim(tok, http.MethodGet, "/scim/v2/Groups/"+grp+"?excludedAttributes=members", nil); strings.Contains(r.raw, "members") || r.str("displayName") != "Ops" {
		t.Errorf("excludedAttributes %s", r.raw)
	}
	// PUT replaces the group, here with no members.
	r = h.scim(tok, http.MethodPut, "/scim/v2/Groups/"+grp, map[string]any{"displayName": "Ops", "members": []any{}})
	expectSCIM(t, "group put", r, http.StatusOK, "")
	if h.membership("org-acme", daveUser, "project", "p-web") != "" {
		t.Error("group PUT without members kept the mapped role")
	}
	// Pagination.
	for _, n := range []string{"erin", "fred", "gina"} {
		expectSCIM(t, "create "+n, h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": n + "@corp.example"}), http.StatusCreated, "")
	}
	r = h.scim(tok, http.MethodGet, "/scim/v2/Users?startIndex=2&count=2", nil)
	if r.total() != 4 || r.body["startIndex"] != float64(2) || r.body["itemsPerPage"] != float64(2) {
		t.Errorf("page %s", r.raw)
	}
	if r := h.scim(tok, http.MethodGet, "/scim/v2/Users?count=0", nil); r.total() != 4 || r.body["itemsPerPage"] != float64(0) {
		t.Errorf("count=0 %s", r.raw)
	}
}

func TestSCIMOrgIsolation(t *testing.T) {
	h, _, _, tokA, tokB := wu611Setup(t, smOpts{})
	h.verifiedDomain("org-b", "corp.example", false) // a pending claim grants nothing
	a := h.scim(tokA, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "ann@corp.example"})
	b := h.scim(tokB, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "ben@beta.example"})
	expectSCIM(t, "a", a, http.StatusCreated, "")
	expectSCIM(t, "b", b, http.StatusCreated, "")
	gB := h.scim(tokB, http.MethodPost, "/scim/v2/Groups", map[string]any{"displayName": "Engineers"})
	expectSCIM(t, "group b", gB, http.StatusCreated, "")
	annID, benID, gBID := a.str("id"), b.str("id"), gB.str("id")

	if r := h.scim(tokA, http.MethodGet, "/scim/v2/Users", nil); r.total() != 1 || strings.Contains(r.raw, "ben@") {
		t.Errorf("A lists %s", r.raw)
	}
	if r := h.scim(tokA, http.MethodGet, usersPath(`userName eq "ben@beta.example"`), nil); r.total() != 0 {
		t.Errorf("A filter finds B: %s", r.raw)
	}
	if r := h.scim(tokA, http.MethodGet, "/scim/v2/Groups", nil); r.total() != 0 {
		t.Errorf("A lists B's groups: %s", r.raw)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/scim/v2/Users/" + benID, nil},
		{http.MethodPut, "/scim/v2/Users/" + benID, map[string]any{"userName": "ben@beta.example", "active": false}},
		{http.MethodPatch, "/scim/v2/Users/" + benID, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}}}},
		{http.MethodDelete, "/scim/v2/Users/" + benID, nil},
		{http.MethodGet, "/scim/v2/Groups/" + gBID, nil},
		{http.MethodPatch, "/scim/v2/Groups/" + gBID, map[string]any{"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": annID}}}}}},
		{http.MethodDelete, "/scim/v2/Groups/" + gBID, nil},
	} {
		expectSCIM(t, "A "+c.method+" "+c.path, h.scim(tokA, c.method, c.path, c.body), http.StatusNotFound, "")
	}
	// B cannot add A's user to its group.
	expectSCIM(t, "B adds A's user", h.scim(tokB, http.MethodPatch, "/scim/v2/Groups/"+gBID, map[string]any{
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]any{{"value": annID}}}},
	}), http.StatusBadRequest, "invalidValue")
	if h.n(`SELECT COUNT(*) FROM scim_group_members`) != 0 {
		t.Error("cross-org member added")
	}
	if h.n(`SELECT COUNT(*) FROM scim_users WHERE id=? AND active=1`, benID) != 1 {
		t.Error("B's user changed by A")
	}
	// B's user is not linked into org-acme: same domain, not verified by B.
	expectSCIM(t, "B links A's domain user", h.scim(tokB, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "ann@corp.example"}), http.StatusConflict, "uniqueness")
}

func TestSCIMLinkingAndRoles(t *testing.T) {
	h, _, _, tok, _ := wu611Setup(t, smOpts{})
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-erin','Erin@Corp.Example','Erin'), ('u-gone','gone@corp.example','Gone')`)
	h.exec(`UPDATE users SET deleted_at='2026-01-01T00:00:00.000Z' WHERE id='u-gone'`)
	before := h.n(`SELECT COUNT(*) FROM users`)
	// Existing user on the org's verified domain: linked, no new user.
	r := h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "erin@corp.example", "emails": []map[string]any{{"value": "erin@corp.example"}}})
	expectSCIM(t, "link", r, http.StatusCreated, "")
	if h.n(`SELECT COUNT(*) FROM scim_users WHERE id=? AND user_id='u-erin'`, r.str("id")) != 1 || h.n(`SELECT COUNT(*) FROM users`) != before {
		t.Error("verified-domain user not linked")
	}
	if !strings.Contains(h.str(`SELECT detail_json FROM audit_log WHERE action='scim.user.created' AND subject='u-erin'`), `"linked":true`) {
		t.Error("link not audited")
	}
	// Existing user outside the org's verified domains: refused, nothing written.
	r = h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "bob", "emails": []map[string]any{{"value": "bob@example.com"}}})
	expectSCIM(t, "unverified existing", r, http.StatusConflict, "uniqueness")
	if !strings.Contains(r.str("detail"), "isn't verified") || h.n(`SELECT COUNT(*) FROM scim_users WHERE user_id='u-bob'`) != 0 {
		t.Errorf("unverified existing %s", r.raw)
	}
	// Deleted account: refused.
	expectSCIM(t, "deleted", h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "gone@corp.example"}), http.StatusConflict, "uniqueness")
	// A new address on an unverified domain creates a user (no link).
	expectSCIM(t, "new outside", h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "x@elsewhere.example"}), http.StatusCreated, "")
	// The same platform user twice in one org: refused.
	expectSCIM(t, "second scim user", h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "erin2", "emails": []map[string]any{{"value": "erin@corp.example"}}}), http.StatusConflict, "uniqueness")
	// Validation.
	expectSCIM(t, "no email", h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "noemail"}), http.StatusBadRequest, "invalidValue")
	expectSCIM(t, "no userName", h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"emails": []map[string]any{{"value": "y@corp.example"}}}), http.StatusBadRequest, "invalidValue")
	expectSCIM(t, "bad json", h.scim(tok, http.MethodPost, "/scim/v2/Users", "{"), http.StatusBadRequest, "invalidSyntax")
	expectSCIM(t, "bad active", h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "z@corp.example", "active": "maybe"}), http.StatusBadRequest, "invalidValue")
	expectSCIM(t, "invalid filter", h.scim(tok, http.MethodGet, usersPath(`userName co "x"`), nil), http.StatusBadRequest, "invalidFilter")
	expectSCIM(t, "invalid filter syntax", h.scim(tok, http.MethodGet, usersPath(`userName eq`), nil), http.StatusBadRequest, "invalidFilter")
	erin := h.scim(tok, http.MethodGet, usersPath(`userName eq "erin@corp.example"`), nil)
	erinID := erin.body["Resources"].([]any)[0].(map[string]any)["id"].(string)
	expectSCIM(t, "bad op", h.scim(tok, http.MethodPatch, "/scim/v2/Users/"+erinID, map[string]any{"Operations": []map[string]any{{"op": "move", "path": "active"}}}), http.StatusBadRequest, "invalidSyntax")
	expectSCIM(t, "no ops", h.scim(tok, http.MethodPatch, "/scim/v2/Users/"+erinID, map[string]any{"Operations": []any{}}), http.StatusBadRequest, "invalidSyntax")
	expectSCIM(t, "remove no path", h.scim(tok, http.MethodPatch, "/scim/v2/Users/"+erinID, map[string]any{"Operations": []map[string]any{{"op": "remove"}}}), http.StatusBadRequest, "noTarget")
	expectSCIM(t, "bad path", h.scim(tok, http.MethodPatch, "/scim/v2/Users/"+erinID, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": `emails[type eq`, "value": "x"}}}), http.StatusBadRequest, "invalidPath")

	// JIT default role is used; an owner-equivalent one falls back to Member.
	h.exec(`INSERT INTO org_sso_settings (org_id, jit_default_role_id) VALUES ('org-acme','r-member')`)
	r = h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "ivy@corp.example"})
	expectSCIM(t, "jit role", r, http.StatusCreated, "")
	if got := h.membership("org-acme", h.scimUser(r.str("id")), "org", "org-acme"); got != "r-member/scim" {
		t.Errorf("JIT default role membership %q", got)
	}
	h.exec(`UPDATE org_sso_settings SET jit_default_role_id='r-owner' WHERE org_id='org-acme'`)
	r = h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "jo@corp.example"})
	if got := h.membership("org-acme", h.scimUser(r.str("id")), "org", "org-acme"); got != roleMemberSys+"/scim" {
		t.Errorf("owner default role membership %q, want Member", got)
	}
	// An existing manual org membership is kept as is on link.
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-kim','kim@corp.example','Kim')`)
	h.exec(`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES ('m-kim','org-acme','u-kim','user','org','org-acme','r-owner')`)
	expectSCIM(t, "link member", h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "kim@corp.example"}), http.StatusCreated, "")
	if got := h.membership("org-acme", "u-kim", "org", "org-acme"); got != "r-owner/manual" {
		t.Errorf("manual membership changed: %q", got)
	}
}

func (h *smHarness) scimUser(scimID string) string {
	h.t.Helper()
	var id string
	if err := h.db.QueryRow(`SELECT user_id FROM scim_users WHERE id=?`, scimID).Scan(&id); err != nil {
		h.t.Fatalf("scim user %s: %v", scimID, err)
	}
	return id
}

func (h *smHarness) str(q string, args ...any) string {
	h.t.Helper()
	var s string
	if err := h.db.QueryRow(q, args...).Scan(&s); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
	return s
}

func TestSCIMRateLimit(t *testing.T) {
	h, _, _, tok, tokB := wu611Setup(t, smOpts{scimRate: config.RateLimit{PerMinute: 60, Burst: 3}})
	for i := 0; i < 3; i++ {
		expectSCIM(t, "within burst", h.scim(tok, http.MethodGet, "/scim/v2/Users", nil), http.StatusOK, "")
	}
	r := h.scim(tok, http.MethodGet, "/scim/v2/Users", nil)
	expectSCIM(t, "over the limit", r, http.StatusTooManyRequests, "")
	if r.hdr.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	// Per token: org-b's token is unaffected.
	expectSCIM(t, "other token", h.scim(tokB, http.MethodGet, "/scim/v2/Users", nil), http.StatusOK, "")
	// Bad tokens share a per-address bucket.
	for i := 0; i < 3; i++ {
		h.scim("bcscim_nope", http.MethodGet, "/scim/v2/Users", nil)
	}
	expectSCIM(t, "bad tokens limited", h.scim("bcscim_nope", http.MethodGet, "/scim/v2/Users", nil), http.StatusTooManyRequests, "")
}

// Q14: a SCIM-provisioned user signing in through the org's own IdP links
// on the verified domain even when the IdP is not trusted for email, and
// sign-in group sync leaves SCIM-managed users alone.
func TestSCIMSignInInterplay(t *testing.T) {
	h, _, d, tok, _ := wu611Setup(t, smOpts{})
	untrusted := oidctest.New(t)
	h.orgIdP("acme-plain", "org-acme", untrusted, false, false)
	if _, err := call(d, user("u-alice", ""), "org-acme", "org.sso.update", map[string]any{"group_sync": true, "jit_enabled": true, "jit_default_role_id": "r-member"}); err != nil {
		t.Fatal(err)
	}
	r := h.scim(tok, http.MethodPost, "/scim/v2/Users", map[string]any{"userName": "lee@corp.example"})
	expectSCIM(t, "create", r, http.StatusCreated, "")
	leeID := r.str("id")
	lee := h.scimUser(leeID)
	g := h.scim(tok, http.MethodPost, "/scim/v2/Groups", map[string]any{"displayName": "Engineers", "members": []map[string]any{{"value": leeID}}})
	expectSCIM(t, "group", g, http.StatusCreated, "")
	if h.membership("org-acme", lee, "team", "t-ops") != roleTeamAdmin+"/idp" {
		t.Fatal("SCIM group mapping missing")
	}

	// First sign-in, untrusted IdP, email not verified, groups present but
	// empty: links to the SCIM user and does not strip the SCIM-driven role.
	untrusted.SetUser(oidctest.User{Subject: "s-lee", Email: "Lee@corp.example", EmailVerified: false, Extra: noGroups})
	if end := h.signIn(oidctest.NewBrowser(t), "acme-plain"); end.Status != http.StatusOK {
		t.Fatalf("sign-in: %d %q", end.Status, end.Body)
	}
	if h.n(`SELECT COUNT(*) FROM identities WHERE user_id=? AND provider='acme-plain'`, lee) != 1 {
		t.Fatal("SCIM user not linked")
	}
	if !strings.Contains(h.str(`SELECT detail_json FROM audit_log WHERE action='identity.linked_by_email' AND actor_id=?`, lee), `"via":"scim"`) {
		t.Error("link audit lacks via=scim")
	}
	if h.membership("org-acme", lee, "team", "t-ops") != roleTeamAdmin+"/idp" {
		t.Error("sign-in group sync removed a SCIM-driven membership")
	}

	// A user without a SCIM row on the same domain and IdP is not linked
	// this way (the untrusted IdP still can't link by email).
	h.exec(`INSERT INTO users (id, email, name) VALUES ('u-mia','mia@corp.example','Mia')`)
	untrusted.SetUser(oidctest.User{Subject: "s-mia", Email: "mia@corp.example", EmailVerified: true, Extra: noGroups})
	h.signIn(oidctest.NewBrowser(t), "acme-plain")
	if h.n(`SELECT COUNT(*) FROM identities WHERE user_id='u-mia'`) != 0 {
		t.Error("non-SCIM user linked by an untrusted IdP")
	}

	// Deactivated: a sign-in neither links a new identity nor gets a JIT
	// membership back.
	expectSCIM(t, "deactivate", h.scim(tok, http.MethodPatch, "/scim/v2/Users/"+leeID, map[string]any{
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	}), http.StatusOK, "")
	untrusted.SetUser(oidctest.User{Subject: "s-lee", Email: "lee@corp.example", EmailVerified: true, Groups: []string{"Engineers"}})
	h.signIn(oidctest.NewBrowser(t), "acme-plain")
	if n := h.n(`SELECT COUNT(*) FROM memberships WHERE org_id='org-acme' AND actor_id=?`, lee); n != 0 {
		t.Errorf("deactivated SCIM user regained %d memberships at sign-in", n)
	}
}

func TestSCIMTokensPage(t *testing.T) {
	h, _, _, _ := wu608Setup(t, smOpts{})
	b := oidctest.NewBrowser(t)
	_, csrf := h.signedIn(b, "u-alice")
	page := "/app/org/org-acme/settings/sso"
	_, _, body := h.get(b, page)
	if !strings.Contains(body, "SCIM provisioning") || !strings.Contains(body, h.app.URL+"/scim/v2") || !strings.Contains(body, "No SCIM tokens yet") {
		t.Fatalf("SCIM section missing")
	}
	form := url.Values{auth.CSRFFormField: {csrf}, "name": {"Entra <prod>"}, "expires_in_days": {"365"}}
	req, _ := http.NewRequest(http.MethodPost, h.app.URL+page+"/scim-tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	created := string(raw)
	if resp.StatusCode != http.StatusOK || !strings.Contains(created, "won't be shown again") || !strings.Contains(created, "Entra &lt;prod&gt;") {
		t.Fatalf("create page %d", resp.StatusCode)
	}
	i := strings.Index(created, "bcscim_")
	token := created[i : i+len("bcscim_")+12+1+64]
	if _, ok := action.ParseSCIMToken(token); !ok {
		t.Fatalf("token on page %q", token)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("token page cacheable")
	}
	// Shown once: the page afterwards lists it without the secret.
	_, _, body = h.get(b, page)
	if strings.Contains(body, token) || !strings.Contains(body, "Entra &lt;prod&gt;") {
		t.Error("token shown again or not listed")
	}
	if r := h.scim(token, http.MethodGet, "/scim/v2/Users", nil); r.status != http.StatusOK {
		t.Fatalf("token from page: %d", r.status)
	}
	var id string
	if err := h.db.QueryRow(`SELECT id FROM scim_tokens WHERE org_id='org-acme'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// CSRF required; then revoke works.
	if resp := h.post(b, page+"/scim-tokens/"+id+"/revoke", "bad"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("revoke without CSRF: %d", resp.StatusCode)
	}
	if resp := h.post(b, page+"/scim-tokens/"+id+"/revoke", csrf); resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "notice=scim_revoked") {
		t.Errorf("revoke: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if r := h.scim(token, http.MethodGet, "/scim/v2/Users", nil); r.status != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", r.status)
	}
	// A member without org.sso can't create one.
	bob := oidctest.NewBrowser(t)
	_, bcsrf := h.signedIn(bob, "u-bob")
	form = url.Values{auth.CSRFFormField: {bcsrf}, "name": {"x"}, "expires_in_days": {"0"}}
	req, _ = http.NewRequest(http.MethodPost, h.app.URL+page+"/scim-tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = bob.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || h.n(`SELECT COUNT(*) FROM scim_tokens`) != 1 {
		t.Errorf("member created a token: %d", resp.StatusCode)
	}
}
