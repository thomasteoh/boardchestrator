package idp_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth/idp"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/event"
	"github.com/thomasteoh/boardchestrator/internal/perm"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

const (
	adminID    = "u-admin"
	userID     = "u-plain"
	orgOwnerID = "u-orgowner"
	ownOrgID   = "org-own"
	theSecret  = "s3cr3t-Client-Value-7f2a"
	newSecret  = "an0ther-Secret-Value-91cd"
)

// fanout records every event and forwards it to the bus.
type fanout struct {
	bus    *event.Bus
	mu     sync.Mutex
	events []action.Event
}

func (f *fanout) Emit(ctx context.Context, ev action.Event) {
	f.mu.Lock()
	f.events = append(f.events, ev)
	f.mu.Unlock()
	event.NewSink(f.bus).Emit(ctx, ev)
}

func (f *fanout) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(f.events)
	return string(b)
}

type actionHarness struct {
	t    *testing.T
	db   *sql.DB
	disp *action.Dispatcher
	ev   *fanout
	bus  *event.Bus
}

func newActionHarness(t *testing.T) *actionHarness {
	t.Helper()
	d := dbtest.New(t)
	for _, q := range []string{
		`INSERT INTO users (id, email) VALUES ('u-admin','admin@example.com'),('u-plain','plain@example.com'),('u-orgowner','owner@example.com')`,
		`INSERT INTO orgs (id, name, slug) VALUES ('org-own','Own','own')`,
		`INSERT INTO roles (id, org_id, name, is_system, grants_json) VALUES ('r-own','org-own','Owner',0,'["*"]')`,
		// Platform admin: Owner ("*") in the platform sentinel org.
		`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id)
		 VALUES ('m1','00000000000000000000000000000000','u-admin','user','org','00000000000000000000000000000000','00000000000000000000000000000000')`,
		// Org owner: Owner ("*") of their own org only.
		`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id)
		 VALUES ('m2','org-own','u-orgowner','user','org','org-own','r-own')`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	bus := event.New()
	ev := &fanout{bus: bus}
	disp := action.New(d,
		action.WithScopeResolver(action.NewDBScopeResolver(d)),
		action.WithPermissionChecker(perm.NewCheckerAdapter(d)),
		action.WithEventSink(ev),
		action.WithSecretKey(encKey),
	)
	return &actionHarness{t: t, db: d, disp: disp, ev: ev, bus: bus}
}

func actor(id string) action.Actor {
	return action.Actor{Type: action.ActorUser, ID: id, IP: "203.0.113.9"}
}

func (h *actionHarness) do(as, name string, in any, opts ...action.Opts) (string, error) {
	h.t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		h.t.Fatal(err)
	}
	o := action.Opts{}
	if len(opts) > 0 {
		o = opts[0]
	}
	out, err := h.disp.Dispatch(context.Background(), actor(as), name, raw, o)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(out)
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b), nil
}

func (h *actionHarness) must(as, name string, in any) string {
	h.t.Helper()
	out, err := h.do(as, name, in)
	if err != nil {
		h.t.Fatalf("%s: %v", name, err)
	}
	return out
}

func (h *actionHarness) auditDump() string {
	h.t.Helper()
	rows, err := h.db.Query(`SELECT action, subject, detail_json FROM audit_log ORDER BY created_at`)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var a, s, d string
		if err := rows.Scan(&a, &s, &d); err != nil {
			h.t.Fatal(err)
		}
		b.WriteString(a + "|" + s + "|" + d + "\n")
	}
	return b.String()
}

func (h *actionHarness) storedSecret(id string) string {
	h.t.Helper()
	var enc string
	if err := h.db.QueryRow(`SELECT client_secret_enc FROM auth_providers WHERE id = ?`, id).Scan(&enc); err != nil {
		h.t.Fatal(err)
	}
	if enc == "" {
		return ""
	}
	plain, err := tenant.Decrypt(encKey, enc)
	if err != nil {
		h.t.Fatal(err)
	}
	return plain
}

func keycloakInput() map[string]any {
	return map[string]any{
		"id": "corp-sso", "preset": "keycloak", "display_name": "Corp SSO",
		"params":    map[string]string{"base_url": "https://sso.example.com/", "realm": "staff"},
		"client_id": "boardchestrator", "client_secret": theSecret,
		"claim_map": map[string]string{"groups": "realm_access.roles"},
	}
}

func TestIdPActionsLifecycle(t *testing.T) {
	h := newActionHarness(t)
	reg := idp.New(idp.Options{DB: h.db, EncKey: encKey, BaseURL: "https://bc.example.com"})
	stop := reg.Watch(h.bus)
	t.Cleanup(stop)
	if ps, err := reg.Providers(context.Background()); err != nil || len(ps) != 0 {
		t.Fatalf("registry before create: %v %v", ps, err)
	}

	out := h.must(adminID, idp.ActionCreate, keycloakInput())
	if out != `{"id":"corp-sso","enabled":true}` {
		t.Errorf("create result = %s", out)
	}
	if got := h.storedSecret("corp-sso"); got != theSecret {
		t.Errorf("stored secret = %q, want the sealed original", got)
	}

	// The registry picks the new provider up from the idp.create event,
	// without a restart.
	waitFor(t, func() bool {
		ps, err := reg.Providers(context.Background())
		return err == nil && len(ps) == 1 && ps[0].ID == "corp-sso"
	})

	list := h.must(adminID, idp.ActionList, map[string]any{})
	var views []idp.ProviderView
	if err := json.Unmarshal([]byte(list), &views); err != nil || len(views) != 1 {
		t.Fatalf("list = %s (%v)", list, err)
	}
	v := views[0]
	if v.Issuer != "https://sso.example.com/realms/staff" || !v.SecretSet || v.ManagedBy != "ui" ||
		v.Params["realm"] != "staff" || v.Params["base_url"] != "https://sso.example.com" ||
		v.ClaimMap["groups"] != "realm_access.roles" || v.TrustEmail || v.AllowSignup || v.Position != 10 {
		t.Errorf("list view = %+v", v)
	}
	get := h.must(adminID, idp.ActionGet, map[string]string{"id": "corp-sso"})
	if !strings.Contains(get, `"secret_set":true`) {
		t.Errorf("get = %s", get)
	}

	// Update with an empty secret keeps the stored one.
	upd := keycloakInput()
	upd["client_secret"] = ""
	upd["display_name"] = "Staff SSO"
	upd["trust_email"] = true
	h.must(adminID, idp.ActionUpdate, upd)
	if got := h.storedSecret("corp-sso"); got != theSecret {
		t.Errorf("secret after blank update = %q, want unchanged", got)
	}
	upd["client_secret"] = newSecret
	h.must(adminID, idp.ActionUpdate, upd)
	if got := h.storedSecret("corp-sso"); got != newSecret {
		t.Errorf("secret after update = %q, want the new one", got)
	}
	get = h.must(adminID, idp.ActionGet, map[string]string{"id": "corp-sso"})
	if !strings.Contains(get, `"display_name":"Staff SSO"`) || !strings.Contains(get, `"trust_email":true`) {
		t.Errorf("get after update = %s", get)
	}

	if out := h.must(adminID, idp.ActionDisable, map[string]string{"id": "corp-sso"}); out != `{"id":"corp-sso","enabled":false}` {
		t.Errorf("disable = %s", out)
	}
	waitFor(t, func() bool {
		ps, _ := reg.Providers(context.Background())
		return len(ps) == 0
	})
	h.must(adminID, idp.ActionEnable, map[string]string{"id": "corp-sso"})
	waitFor(t, func() bool {
		ps, _ := reg.Providers(context.Background())
		return len(ps) == 1
	})

	// Discovery-free sanity: the rebuilt connector is usable by id.
	if _, err := reg.Connector(context.Background(), "corp-sso"); err != nil {
		t.Errorf("connector after enable: %v", err)
	}

	h.must(adminID, idp.ActionDelete, map[string]string{"id": "corp-sso"})
	var n int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM auth_providers`).Scan(&n)
	if n != 0 {
		t.Errorf("rows after delete = %d", n)
	}

	// Every mutation is audited (ImpactHigh), and neither secret appears in
	// any result, event payload or audit row.
	audit := h.auditDump()
	for _, a := range []string{idp.ActionCreate, idp.ActionUpdate, idp.ActionDisable, idp.ActionEnable, idp.ActionDelete} {
		if !strings.Contains(audit, a+"|corp-sso|") {
			t.Errorf("no audit row for %s:\n%s", a, audit)
		}
	}
	for name, s := range map[string]string{"results": list + get + out, "events": h.ev.all(), "audit": audit} {
		for _, secret := range []string{theSecret, newSecret} {
			if strings.Contains(s, secret) {
				t.Errorf("client secret leaked into %s", name)
			}
		}
	}
	// Admin-only reads emit events without their result.
	if strings.Contains(h.ev.all(), "realm_access.roles") || strings.Contains(h.ev.all(), "sso.example.com") {
		t.Errorf("read results leaked into events: %s", h.ev.all())
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestIdPActionsPermission(t *testing.T) {
	h := newActionHarness(t)
	h.must(adminID, idp.ActionCreate, keycloakInput())
	cases := []struct {
		as   string
		opts action.Opts
	}{
		{userID, action.Opts{}},
		{orgOwnerID, action.Opts{}},
		// An org owner holds "*" in their org; passing it must not turn
		// into a platform grant.
		{orgOwnerID, action.Opts{Org: ownOrgID}},
		{adminID, action.Opts{Org: ownOrgID}},
	}
	for _, c := range cases {
		for _, name := range []string{idp.ActionList, idp.ActionGet, idp.ActionCreate, idp.ActionUpdate,
			idp.ActionDelete, idp.ActionEnable, idp.ActionDisable, idp.ActionDiscover} {
			in := keycloakInput()
			if name == idp.ActionCreate {
				in["id"] = "other"
			}
			if name == idp.ActionList {
				in = map[string]any{}
			}
			if name == idp.ActionDiscover || name == idp.ActionGet || name == idp.ActionDelete ||
				name == idp.ActionEnable || name == idp.ActionDisable {
				in = map[string]any{"id": "corp-sso"}
			}
			_, err := h.do(c.as, name, in, c.opts)
			if !errors.Is(err, action.ErrForbidden) {
				t.Errorf("%s as %s (org %q): err = %v, want ErrForbidden", name, c.as, c.opts.Org, err)
			}
			// With an org id, the org's "*" grant passes the permission
			// check; the platform-only guard must still refuse.
			if c.as == orgOwnerID && c.opts.Org != "" && (err == nil || !strings.Contains(err.Error(), "organisation")) {
				t.Errorf("%s as %s with org: not refused by the platform guard: %v", name, c.as, err)
			}
		}
	}
	var n int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM auth_providers WHERE id = 'other' OR enabled = 0`).Scan(&n)
	if n != 0 {
		t.Error("a denied call changed state")
	}
}

func TestIdPActionsEnvManagedReadOnly(t *testing.T) {
	h := newActionHarness(t)
	insertRow(t, h.db, row{id: "google", preset: "google", issuer: "https://accounts.google.com",
		clientID: "g", secret: "env-secret", managedBy: "env", trust: 1, signup: 1})
	in := map[string]any{"id": "google", "preset": "google", "client_id": "x"}
	for _, name := range []string{idp.ActionUpdate, idp.ActionDelete, idp.ActionEnable, idp.ActionDisable} {
		args := map[string]any{"id": "google"}
		if name == idp.ActionUpdate {
			args = in
		}
		_, err := h.do(adminID, name, args)
		if !errors.Is(err, action.ErrInvalidInput) || !errors.Is(err, idp.ErrEnvManaged) {
			t.Errorf("%s on env row: err = %v, want ErrEnvManaged", name, err)
		}
	}
	// Creating over an env id is refused too.
	if _, err := h.do(adminID, idp.ActionCreate, in); !errors.Is(err, action.ErrInvalidInput) {
		t.Errorf("create over env id: %v", err)
	}
	// Listed read-only.
	list := h.must(adminID, idp.ActionList, map[string]any{})
	if !strings.Contains(list, `"managed_by":"env"`) || strings.Contains(list, "env-secret") {
		t.Errorf("list = %s", list)
	}
}

func TestIdPActionsValidation(t *testing.T) {
	h := newActionHarness(t)
	base := func(over map[string]any) map[string]any {
		in := map[string]any{"id": "ok-id", "preset": "generic", "client_id": "c",
			"params": map[string]string{"issuer": "https://idp.example.com"}}
		for k, v := range over {
			if v == nil {
				delete(in, k)
				continue
			}
			in[k] = v
		}
		return in
	}
	bad := map[string]map[string]any{
		"upper-case id":       base(map[string]any{"id": "Corp"}),
		"underscore id":       base(map[string]any{"id": "corp_sso"}),
		"leading hyphen id":   base(map[string]any{"id": "-corp"}),
		"empty id":            base(map[string]any{"id": ""}),
		"slash id":            base(map[string]any{"id": "a/b"}),
		"reserved id logout":  base(map[string]any{"id": "logout"}),
		"reserved id saml":    base(map[string]any{"id": "saml"}),
		"unknown preset":      base(map[string]any{"preset": "facebook"}),
		"empty preset":        base(map[string]any{"preset": ""}),
		"kind mismatch":       base(map[string]any{"kind": "github"}),
		"saml kind":           base(map[string]any{"kind": "saml"}),
		"http issuer":         base(map[string]any{"params": map[string]string{"issuer": "http://idp.example.com"}}),
		"javascript issuer":   base(map[string]any{"params": map[string]string{"issuer": "javascript:alert(1)"}}),
		"issuer with query":   base(map[string]any{"params": map[string]string{"issuer": "https://idp.example.com/?a=b"}}),
		"missing param":       base(map[string]any{"preset": "keycloak", "params": map[string]string{"base_url": "https://sso.example.com"}}),
		"unknown param":       base(map[string]any{"params": map[string]string{"issuer": "https://idp.example.com", "realm": "x"}}),
		"template injection":  base(map[string]any{"preset": "keycloak", "params": map[string]string{"base_url": "https://sso.example.com", "realm": "a{b}"}}),
		"no client id":        base(map[string]any{"client_id": ""}),
		"control chars":       base(map[string]any{"display_name": "Corp\nSSO"}),
		"scopes without oidc": base(map[string]any{"scopes": "email profile"}),
		"bad scope":           base(map[string]any{"scopes": "openid \"x\""}),
		"unknown claim":       base(map[string]any{"claim_map": map[string]string{"role": "x"}}),
		"tenants not entra":   base(map[string]any{"allowed_tenants": []string{"11111111-2222-3333-4444-555555555555"}}),
		"tenant not a guid":   base(map[string]any{"preset": "microsoft", "params": map[string]string{"tenant": "organizations"}, "allowed_tenants": []string{"evil"}}),
		"github needs secret": base(map[string]any{"preset": "github", "params": nil}),
		"unknown field":       base(map[string]any{"client_secret_enc": "x"}),
		"secret spaces":       base(map[string]any{"client_secret": " padded "}),
	}
	for name, in := range bad {
		if _, err := h.do(adminID, idp.ActionCreate, in); !errors.Is(err, action.ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}
	var n int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM auth_providers`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows created by invalid input", n)
	}

	// Valid variants.
	h.must(adminID, idp.ActionCreate, base(map[string]any{"preset": "microsoft", "id": "entra",
		"params": map[string]string{"tenant": "organizations"}, "allowed_tenants": []string{"11111111-2222-3333-4444-555555555555"}}))
	h.must(adminID, idp.ActionCreate, base(map[string]any{"preset": "github", "id": "gh", "params": nil, "client_secret": "x"}))
	h.must(adminID, idp.ActionCreate, base(map[string]any{"enabled": false}))

	// Updates can't flip enabled or change kind, and need an existing id.
	if _, err := h.do(adminID, idp.ActionUpdate, base(map[string]any{"enabled": true})); !errors.Is(err, action.ErrInvalidInput) {
		t.Errorf("update with enabled: %v", err)
	}
	if _, err := h.do(adminID, idp.ActionUpdate, base(map[string]any{"preset": "github", "params": nil})); !errors.Is(err, action.ErrInvalidInput) {
		t.Errorf("update oidc→github: %v", err)
	}
	if _, err := h.do(adminID, idp.ActionUpdate, base(map[string]any{"id": "missing"})); !errors.Is(err, action.ErrInvalidInput) {
		t.Errorf("update missing: %v", err)
	}
	// Duplicate create.
	if _, err := h.do(adminID, idp.ActionCreate, base(nil)); !errors.Is(err, action.ErrInvalidInput) {
		t.Errorf("duplicate create: %v", err)
	}
}

func TestIdPDeleteRefusedWhileIdentitiesExist(t *testing.T) {
	h := newActionHarness(t)
	h.must(adminID, idp.ActionCreate, keycloakInput())
	if _, err := h.db.Exec(`INSERT INTO identities (id, user_id, provider, subject) VALUES ('i1','u-plain','corp-sso','sub-1')`); err != nil {
		t.Fatal(err)
	}
	_, err := h.do(adminID, idp.ActionDelete, map[string]string{"id": "corp-sso"})
	if !errors.Is(err, action.ErrInvalidInput) || !strings.Contains(err.Error(), "disable") {
		t.Fatalf("delete with identities: %v", err)
	}
	list := h.must(adminID, idp.ActionList, map[string]any{})
	if !strings.Contains(list, `"identity_count":1`) {
		t.Errorf("list = %s", list)
	}
	// Disabling is the supported path.
	h.must(adminID, idp.ActionDisable, map[string]string{"id": "corp-sso"})
}

func TestIdPDiscover(t *testing.T) {
	h := newActionHarness(t)
	fake := oidctest.New(t)

	out := h.must(adminID, idp.ActionDiscover, map[string]any{"preset": "generic", "params": map[string]string{"issuer": fake.Issuer()}})
	var res idp.DiscoverResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.TokenEndpoint == "" || res.JWKSURI == "" || !strings.HasPrefix(res.AuthorizationEndpoint, fake.Issuer()) || res.Ref != "" {
		t.Errorf("discover = %+v", res)
	}

	// A saved provider by id.
	insertRow(t, h.db, row{id: "fake", preset: "generic", issuer: fake.Issuer(), clientID: "c"})
	out = h.must(adminID, idp.ActionDiscover, map[string]any{"id": "fake"})
	if !strings.Contains(out, `"ok":true`) {
		t.Errorf("discover by id = %s", out)
	}

	// Failures report only a reference code: wrong issuer path (404), and a
	// cloud metadata address the dialer refuses.
	for _, iss := range []string{fake.Issuer() + "/nope", "https://169.254.169.254/latest"} {
		out = h.must(adminID, idp.ActionDiscover, map[string]any{"preset": "generic", "params": map[string]string{"issuer": iss}})
		res = idp.DiscoverResult{}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatal(err)
		}
		if res.OK || len(res.Ref) != 10 || res.TokenEndpoint != "" {
			t.Errorf("discover %s = %s", iss, out)
		}
		for _, leak := range []string{"404", "not allowed", "status", "dial"} {
			if strings.Contains(out, leak) {
				t.Errorf("discover %s leaked %q: %s", iss, leak, out)
			}
		}
	}

	if _, err := h.do(adminID, idp.ActionDiscover, map[string]any{"preset": "github"}); !errors.Is(err, action.ErrInvalidInput) {
		t.Errorf("github discover: %v", err)
	}
}
