package idp_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/idp"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/config"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/event"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

const flowSecret = "test-secret-key-for-flow-cookies"

var encKey = tenant.PadKey(flowSecret)

// captureSource wraps the registry so tests can see each provider's last
// assertion and Complete error.
type captureSource struct {
	inner auth.ConnectorSource
	mu    sync.Mutex
	got   map[string]*auth.Assertion
	errs  map[string]error
}

func (c *captureSource) Connector(ctx context.Context, id string) (auth.Connector, error) {
	conn, err := c.inner.Connector(ctx, id)
	if err != nil {
		return nil, err
	}
	return captureConn{Connector: conn, src: c}, nil
}

func (c *captureSource) last(id string) (*auth.Assertion, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.got[id], c.errs[id]
}

type captureConn struct {
	auth.Connector
	src *captureSource
}

func (cc captureConn) Complete(ctx context.Context, r *http.Request, f *auth.Flow) (*auth.Assertion, error) {
	a, err := cc.Connector.Complete(ctx, r, f)
	cc.src.mu.Lock()
	cc.src.got[cc.ID()], cc.src.errs[cc.ID()] = a, err
	cc.src.mu.Unlock()
	return a, err
}

type harness struct {
	t   *testing.T
	db  *sql.DB
	app *httptest.Server
	reg *idp.Registry
	cap *captureSource
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	d := dbtest.New(t)
	if _, err := d.Exec(`UPDATE platform_settings SET bootstrap_done = 1`); err != nil {
		t.Fatal(err)
	}
	var router http.Handler
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { router.ServeHTTP(w, r) }))
	t.Cleanup(app.Close)

	reg := idp.New(idp.Options{DB: d, EncKey: encKey, BaseURL: app.URL})
	cs := &captureSource{inner: reg, got: map[string]*auth.Assertion{}, errs: map[string]error{}}
	store := auth.NewSessionStore(d)
	h, err := auth.NewHandler(auth.HandlerConfig{
		DB: d, Sessions: store, SecretKey: flowSecret, EncKey: encKey, BaseURL: app.URL, Providers: cs,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	sc := auth.SessionConfig{Store: store, Secret: "0123456789abcdef0123456789abcdef"}
	r.Use(sc.Session())
	h.Routes(r)
	r.Get("/app", func(w http.ResponseWriter, r *http.Request) {
		s, ok := auth.SessionFrom(r.Context())
		if !ok {
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "user="+s.UserID)
	})
	r.Get("/app/*", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "deep")
	})
	router = r
	return &harness{t: t, db: d, app: app, reg: reg, cap: cs}
}

// row is an auth_providers row to insert (UI-managed unless stated).
type row struct {
	id, kind, preset, issuer, clientID, secret, scopes, claimMap, tenants, managedBy string
	trust, signup                                                                    int
	enabled                                                                          *int
}

func (h *harness) insert(r row) {
	h.t.Helper()
	insertRow(h.t, h.db, r)
	h.reg.Invalidate()
}

func insertRow(t *testing.T, d *sql.DB, r row) {
	t.Helper()
	if r.kind == "" {
		r.kind = idp.KindOIDC
	}
	if r.claimMap == "" {
		r.claimMap = "{}"
	}
	if r.tenants == "" {
		r.tenants = "[]"
	}
	if r.managedBy == "" {
		r.managedBy = "ui"
	}
	enabled := 1
	if r.enabled != nil {
		enabled = *r.enabled
	}
	secretEnc := ""
	if r.secret != "" {
		var err error
		if secretEnc, err = tenant.Encrypt(encKey, r.secret); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Exec(`INSERT INTO auth_providers (id, kind, preset, display_name, enabled, managed_by, issuer,
		client_id, client_secret_enc, scopes, claim_map_json, trust_email, allow_signup, allowed_tenants_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.id, r.kind, r.preset, r.id, enabled, r.managedBy, r.issuer, r.clientID, secretEnc, r.scopes,
		r.claimMap, r.trust, r.signup, r.tenants); err != nil {
		t.Fatalf("insert %s: %v", r.id, err)
	}
}

// oidcRow is a trusted, open-sign-up row pointing at srv.
func oidcRow(id, preset string, srv *oidctest.Server) row {
	return row{id: id, preset: preset, issuer: srv.Issuer(), clientID: srv.ClientID, secret: srv.ClientSecret, trust: 1, signup: 1}
}

func (h *harness) login(id string) []oidctest.Step {
	h.t.Helper()
	steps, err := oidctest.NewBrowser(h.t).Follow(h.app.URL+"/auth/"+id, 5, nil)
	if err != nil {
		h.t.Fatalf("login %s: %v", id, err)
	}
	return steps
}

func landed(steps []oidctest.Step) bool {
	end := steps[len(steps)-1]
	return end.Status == http.StatusOK && strings.HasPrefix(end.Body, "user=")
}

func (h *harness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(q, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// Every OIDC preset logs in end to end through the registry: issuer, scopes,
// redirect URI and claim map (including groups) come from the row + preset.
func TestPresetProvidersLogInThroughRegistry(t *testing.T) {
	h := newHarness(t)
	wantGroups := map[string][]string{
		"google": nil, "microsoft": {"g1", "g2"}, "gitlab": {"gl-direct"}, "okta": {"g1", "g2"},
		"auth0": nil, "keycloak": {"g1", "g2"}, "zitadel": {"z-editor", "z-owner"},
		"authentik": {"g1", "g2"}, "generic": {"g1", "g2"},
	}
	for _, preset := range idp.PresetIDs {
		p, _ := idp.LookupPreset(preset)
		if p.Kind != idp.KindOIDC {
			continue
		}
		t.Run(preset, func(t *testing.T) {
			srv := oidctest.New(t)
			srv.SetUser(oidctest.User{
				Subject: preset + "-sub", Email: preset + "@example.com", EmailVerified: true, Name: "N " + preset,
				Groups: []string{"g2", "g1"}, SID: "sid-" + preset,
				Extra: map[string]any{
					"groups_direct":                     []string{"gl-direct"},
					"urn:zitadel:iam:org:project:roles": map[string]any{"z-owner": map[string]any{"1": "x"}, "z-editor": map[string]any{"1": "x"}},
				},
			})
			r := oidcRow(preset, preset, srv)
			if preset == "microsoft" {
				// Entra never vouches for email by default; this tenant maps
				// a verification claim explicitly.
				r.claimMap = `{"email_verified": "email_verified"}`
			}
			h.insert(r)
			if !landed(h.login(preset)) {
				_, err := h.cap.last(preset)
				t.Fatalf("login did not land: %v", err)
			}
			a, _ := h.cap.last(preset)
			if a.Subject != preset+"-sub" || a.Email != preset+"@example.com" || !a.EmailVerified ||
				a.Name != "N "+preset || a.SID != "sid-"+preset || a.IDTokenRaw == "" {
				t.Errorf("assertion %+v", a)
			}
			if !reflect.DeepEqual(a.Groups, wantGroups[preset]) {
				t.Errorf("groups = %v, want %v", a.Groups, wantGroups[preset])
			}
			ar := srv.AuthorizeRequests()
			if len(ar) != 1 || ar[0].Scope != strings.Join(p.Scopes, " ") ||
				ar[0].RedirectURI != h.app.URL+"/auth/"+preset+"/callback" || ar[0].CodeChallengeMethod != "S256" {
				t.Errorf("authorize request %+v", ar)
			}
			if n := h.count(`SELECT COUNT(*) FROM identities WHERE provider = ? AND subject = ?`, preset, preset+"-sub"); n != 1 {
				t.Errorf("identities = %d", n)
			}
			if n := h.count(`SELECT COUNT(*) FROM sessions WHERE provider_id = ? AND auth_method = 'oidc' AND idp_sid = ?`, preset, "sid-"+preset); n != 1 {
				t.Errorf("sessions with provenance = %d", n)
			}
		})
	}
}

// Microsoft's email is unverified unless the claim map says otherwise, so a
// new user cannot sign up through the default preset.
func TestMicrosoftEmailUnverifiedByDefault(t *testing.T) {
	h := newHarness(t)
	srv := oidctest.New(t)
	srv.SetUser(oidctest.User{Subject: "ms-1", Email: "ms@example.com", EmailVerified: true})
	h.insert(oidcRow("entra", "microsoft", srv))
	steps := h.login("entra")
	if end := steps[len(steps)-1]; end.Status != http.StatusForbidden {
		t.Fatalf("status %d", end.Status)
	}
	if a, _ := h.cap.last("entra"); a == nil || a.EmailVerified {
		t.Errorf("assertion %+v", a)
	}
	if n := h.count(`SELECT COUNT(*) FROM identities WHERE provider = 'entra'`); n != 0 {
		t.Errorf("identity created")
	}
}

// Group extraction honours the row's claim map: arrays, single strings,
// object-keyed maps and dotted paths into nested claims.
func TestGroupClaimShapes(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		id, claimMap string
		extra        map[string]any
		want         []string
	}{
		{"array", `{}`, map[string]any{"groups": []string{"b", "a"}}, []string{"a", "b"}},
		{"single", `{"groups": "role"}`, map[string]any{"role": "admin"}, []string{"admin"}},
		{"object", `{"groups": "urn:zitadel:iam:org:project:roles"}`,
			map[string]any{"urn:zitadel:iam:org:project:roles": map[string]any{"reader": map[string]any{"9": "d"}}}, []string{"reader"}},
		{"dotted", `{"groups": "realm_access.roles"}`,
			map[string]any{"realm_access": map[string]any{"roles": []string{"kc-admin", "kc-user"}}}, []string{"kc-admin", "kc-user"}},
		{"namespaced", `{"groups": "https://example.com/groups"}`,
			map[string]any{"https://example.com/groups": []string{"ns"}}, []string{"ns"}},
		{"custom-email", `{"email": "upn", "name": "profile.display"}`,
			map[string]any{"upn": "upn@example.com", "profile": map[string]any{"display": "Upn User"}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			srv := oidctest.New(t)
			srv.SetUser(oidctest.User{Subject: tc.id, Email: tc.id + "@example.com", EmailVerified: true, Extra: tc.extra})
			r := oidcRow(tc.id, "generic", srv)
			r.claimMap = tc.claimMap
			h.insert(r)
			if !landed(h.login(tc.id)) {
				_, err := h.cap.last(tc.id)
				t.Fatalf("login failed: %v", err)
			}
			a, _ := h.cap.last(tc.id)
			if !reflect.DeepEqual(a.Groups, tc.want) {
				t.Errorf("groups = %v, want %v", a.Groups, tc.want)
			}
			if tc.id == "custom-email" && (a.Email != "upn@example.com" || a.Name != "Upn User") {
				t.Errorf("custom claim map: email %q name %q", a.Email, a.Name)
			}
		})
	}
}

// entraProxy fronts srv at <proxy>/organizations/v2.0, the shape of Entra's
// multi-tenant issuer, so discovery is fetched from a pseudo-tenant URL.
func entraProxy(t *testing.T, srv *oidctest.Server) string {
	t.Helper()
	target, _ := url.Parse(srv.URL())
	rp := httputil.NewSingleHostReverseProxy(target)
	px := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/organizations/v2.0")
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(px.Close)
	return px.URL
}

func TestEntraMultiTenant(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name, tenants, tid, issTenant string
		ok                            bool
		errHas                        string
	}{
		{"matching tid", `["tid-a","tid-b"]`, "tid-a", "tid-a", true, ""},
		{"iss of another tenant", `["tid-a","tid-b"]`, "tid-a", "tid-b", false, "does not match"},
		{"tenant not allowed", `["tid-a","tid-b"]`, "tid-evil", "tid-evil", false, "not allowed"},
		{"no tid", `[]`, "", "tid-a", false, "tid"},
		{"any tenant when list empty", `[]`, "tid-z", "tid-z", true, ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := oidctest.New(t)
			px := entraProxy(t, srv)
			claims := map[string]any{"iss": px + "/" + tc.issTenant + "/v2.0", "tid": tc.tid}
			if tc.tid == "" {
				claims["tid"] = nil
			}
			srv.SetMisbehaviour(oidctest.Misbehaviour{Claims: claims})
			id := fmt.Sprintf("entra-%d", i)
			srv.SetUser(oidctest.User{Subject: id, Email: id + "@example.com", EmailVerified: true})
			h.insert(row{id: id, preset: "microsoft", issuer: px + "/organizations/v2.0", clientID: srv.ClientID,
				secret: srv.ClientSecret, claimMap: `{"email_verified": "email_verified"}`, tenants: tc.tenants,
				trust: 1, signup: 1})
			steps := h.login(id)
			_, err := h.cap.last(id)
			if landed(steps) != tc.ok {
				t.Fatalf("landed=%v, want %v (err %v)", landed(steps), tc.ok, err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), tc.errHas)) {
				t.Errorf("err = %v, want %q", err, tc.errHas)
			}
		})
	}
}

// A provider whose discovery fails (or whose row is broken) fails only its
// own logins.
func TestBrokenProviderIsolated(t *testing.T) {
	h := newHarness(t)
	good := oidctest.New(t)
	h.insert(row{id: "unreachable", preset: "generic", issuer: "http://127.0.0.1:1", clientID: "x", trust: 1, signup: 1})
	h.insert(row{id: "badpreset", preset: "nonsense", issuer: good.Issuer(), clientID: "x", trust: 1, signup: 1})
	h.insert(oidcRow("good", "generic", good))

	for _, id := range []string{"unreachable", "badpreset"} {
		steps := h.login(id)
		end := steps[len(steps)-1]
		if end.Status != http.StatusBadGateway || !strings.Contains(end.Body, "Reference:") ||
			strings.Contains(end.Body, "127.0.0.1") || strings.Contains(end.Body, "nonsense") {
			t.Errorf("%s: status %d body %q", id, end.Status, end.Body)
		}
	}
	if !landed(h.login("good")) {
		t.Fatal("good provider failed")
	}
	ps, err := h.reg.Providers(context.Background())
	if err != nil || len(ps) != 3 {
		t.Errorf("providers %v %v", ps, err)
	}
	// Unknown and disabled providers are 404s.
	off := 0
	h.insert(row{id: "off", preset: "generic", issuer: good.Issuer(), clientID: "x", enabled: &off})
	for _, id := range []string{"nope", "off"} {
		steps := h.login(id)
		if s := steps[len(steps)-1].Status; s != http.StatusNotFound {
			t.Errorf("%s: status %d", id, s)
		}
	}
}

func TestPolicyComesFromRow(t *testing.T) {
	h := newHarness(t)
	srv := oidctest.New(t)
	h.insert(row{id: "closed", preset: "generic", issuer: srv.Issuer(), clientID: "x"})
	h.insert(row{id: "trusted", preset: "generic", issuer: srv.Issuer(), clientID: "x", trust: 1})
	ctx := context.Background()
	for id, want := range map[string]auth.ResolvePolicy{
		"closed": {}, "trusted": {TrustEmail: true},
	} {
		c, err := h.reg.Connector(ctx, id)
		if err != nil || c.Policy() != want || c.AuthMethod() != auth.AuthMethodOIDC {
			t.Errorf("%s: %v %+v", id, err, c)
		}
	}
	// A closed provider cannot create a user.
	srv.SetUser(oidctest.User{Subject: "new", Email: "new@example.com", EmailVerified: true})
	if landed(h.login("closed")) {
		t.Error("closed provider signed a new user up")
	}
}

// Existing google/github identities (pre-registry) still resolve once the
// env-seeded rows exist: the ids are unchanged.
func TestExistingIdentitiesResolveAfterSeeding(t *testing.T) {
	h := newHarness(t)
	srv := oidctest.New(t)
	if _, err := h.db.Exec(`INSERT INTO users (id, email, name) VALUES ('u-old', 'old@example.com', 'Old')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO identities (id, user_id, provider, subject, email) VALUES
		('i-g', 'u-old', 'google', 'g-sub', 'old@example.com'),
		('i-h', 'u-old', 'github', '4242', 'old@example.com')`); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		GoogleClientID: srv.ClientID, GoogleClientSecret: srv.ClientSecret, GoogleIssuer: srv.Issuer(),
		GitHubClientID: "gh-id", GitHubClientSecret: "gh-secret", GitHubWebBase: "http://127.0.0.1:9",
		AllowSignup: true, // config.Load's BC_ALLOW_SIGNUP default
	}
	if err := idp.SeedFromConfig(context.Background(), h.db, encKey, cfg); err != nil {
		t.Fatal(err)
	}
	h.reg.Invalidate()

	// The Google identity hit resolves to the same user even with a new email.
	srv.SetUser(oidctest.User{Subject: "g-sub", Email: "changed@example.com", EmailVerified: true})
	steps := h.login("google")
	if !landed(steps) || steps[len(steps)-1].Body != "user=u-old" {
		t.Fatalf("google login: %+v", steps[len(steps)-1])
	}
	if n := h.count(`SELECT COUNT(*) FROM users WHERE id <> 'ffffffffffffffffffffffffffffffff'`); n != 1 {
		t.Errorf("users = %d", n)
	}

	// GitHub is built from its row: same id, OAuth endpoints from the
	// issuer, trusted + open sign-up preserved (WU-601 behaviour).
	c, err := h.reg.Connector(context.Background(), "github")
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthMethod() != auth.AuthMethodGitHub || c.Policy() != (auth.ResolvePolicy{TrustEmail: true, AllowSignup: true}) {
		t.Errorf("github connector %s %+v", c.AuthMethod(), c.Policy())
	}
	dest, err := c.Begin(context.Background(), &auth.Flow{State: "st"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(dest)
	if u.Host != "127.0.0.1:9" || u.Query().Get("redirect_uri") != h.app.URL+"/auth/github/callback" ||
		u.Query().Get("client_id") != "gh-id" {
		t.Errorf("github begin %s", dest)
	}
}

func TestSeedFromConfig(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	reg := idp.New(idp.Options{DB: d, EncKey: encKey, BaseURL: "https://bc.example.com"})
	insertRow(t, d, row{id: "taken", preset: "generic", issuer: "https://ui.example.com", clientID: "ui-client"})

	yes, no := true, false
	cfg := &config.Config{OIDCProviders: []config.OIDCEnvProvider{
		{ID: "corp", Issuer: "https://sso.example.com/realms/staff", ClientID: "corp-id", ClientSecret: "corp-secret",
			Preset: "keycloak", DisplayName: "Corp", TrustEmail: &yes, AllowSignup: &no, GroupsClaim: "realm_access.roles"},
		{ID: "gl", ClientID: "gl-id", Preset: "gitlab"}, // issuer from the preset default
		{ID: "taken", Issuer: "https://env.example.com", ClientID: "env-client"},
		{ID: "needs-issuer", ClientID: "x", Preset: "okta"},
		{ID: "logout", Issuer: "https://x.example.com", ClientID: "x"},
	}, AllowSignup: true}
	err := idp.SeedFromConfig(ctx, d, encKey, cfg)
	if err == nil || !strings.Contains(err.Error(), `"taken"`) || !strings.Contains(err.Error(), "NEEDS_ISSUER") ||
		!strings.Contains(err.Error(), "reserved") {
		t.Fatalf("seed err = %v", err)
	}

	var (
		kind, preset, name, managed, issuer, secretEnc, scopes, claimMap string
		trust, signup, enabled                                           int
	)
	if err := d.QueryRow(`SELECT kind, preset, display_name, managed_by, issuer, client_secret_enc, scopes,
		claim_map_json, trust_email, allow_signup, enabled FROM auth_providers WHERE id = 'corp'`).Scan(
		&kind, &preset, &name, &managed, &issuer, &secretEnc, &scopes, &claimMap, &trust, &signup, &enabled); err != nil {
		t.Fatal(err)
	}
	if kind != "oidc" || preset != "keycloak" || name != "Corp" || managed != "env" || enabled != 1 ||
		issuer != "https://sso.example.com/realms/staff" || scopes != "openid email profile" ||
		claimMap != `{"groups":"realm_access.roles"}` || trust != 1 || signup != 0 {
		t.Errorf("corp row: %s %s %s %s %s %s %s %d %d %d", kind, preset, name, managed, issuer, scopes, claimMap, trust, signup, enabled)
	}
	if strings.Contains(secretEnc, "corp-secret") {
		t.Error("secret stored in plaintext")
	}
	if pt, err := tenant.Decrypt(encKey, secretEnc); err != nil || pt != "corp-secret" {
		t.Errorf("secret decrypts to %q, %v", pt, err)
	}
	var glIssuer string
	var glTrust, glSignup int
	if err := d.QueryRow(`SELECT issuer, trust_email, allow_signup FROM auth_providers WHERE id = 'gl'`).Scan(&glIssuer, &glTrust, &glSignup); err != nil {
		t.Fatal(err)
	}
	if glIssuer != "https://gitlab.com" || glTrust != 1 || glSignup != 1 {
		t.Errorf("gl row %s %d %d", glIssuer, glTrust, glSignup)
	}
	var takenClient, takenManaged string
	if err := d.QueryRow(`SELECT client_id, managed_by FROM auth_providers WHERE id = 'taken'`).Scan(&takenClient, &takenManaged); err != nil {
		t.Fatal(err)
	}
	if takenClient != "ui-client" || takenManaged != "ui" {
		t.Errorf("UI row overwritten: %s %s", takenClient, takenManaged)
	}
	if c, err := reg.Connector(ctx, "corp"); err != nil || c.Policy() != (auth.ResolvePolicy{TrustEmail: true}) {
		t.Fatalf("corp connector: %v", err)
	}

	// Reseeding unchanged config keeps the ciphertext (no churn).
	cfg.OIDCProviders = cfg.OIDCProviders[:2]
	if err := idp.SeedFromConfig(ctx, d, encKey, cfg); err != nil {
		t.Fatal(err)
	}
	var again string
	_ = d.QueryRow(`SELECT client_secret_enc FROM auth_providers WHERE id = 'corp'`).Scan(&again)
	if again != secretEnc {
		t.Error("ciphertext rewritten for an unchanged secret")
	}

	// Removing corp from the environment disables (never deletes) it.
	cfg.OIDCProviders = cfg.OIDCProviders[1:]
	if err := idp.SeedFromConfig(ctx, d, encKey, cfg); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT enabled FROM auth_providers WHERE id = 'corp'`).Scan(&enabled); err != nil || enabled != 0 {
		t.Errorf("corp enabled=%d err=%v", enabled, err)
	}
	reg.Invalidate()
	if _, err := reg.Connector(ctx, "corp"); !errors.Is(err, auth.ErrUnknownProvider) {
		t.Errorf("disabled corp still served: %v", err)
	}
	var uiEnabled int
	_ = d.QueryRow(`SELECT enabled FROM auth_providers WHERE id = 'taken'`).Scan(&uiEnabled)
	if uiEnabled != 1 {
		t.Error("UI row disabled by env seeding")
	}
}

// idp.* events on the bus invalidate the registry's cache.
func TestRegistryInvalidatesOnIdPEvents(t *testing.T) {
	d := dbtest.New(t)
	ctx := context.Background()
	reg := idp.New(idp.Options{DB: d, EncKey: encKey, BaseURL: "https://bc.example.com"})
	bus := event.New()
	stop := reg.Watch(bus)
	defer stop()

	if ps, _ := reg.Providers(ctx); len(ps) != 0 {
		t.Fatalf("providers %v", ps)
	}
	insertRow(t, d, row{id: "late", preset: "generic", issuer: "https://late.example.com", clientID: "x"})
	bus.Publish(event.Event{Name: "task.update"})
	if ps, _ := reg.Providers(ctx); len(ps) != 0 {
		t.Fatal("unrelated event invalidated the cache")
	}
	bus.Publish(event.Event{Name: "idp.create"})
	deadline := time.Now().Add(2 * time.Second)
	for {
		ps, _ := reg.Providers(ctx)
		if len(ps) == 1 && ps[0].ID == "late" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("registry not invalidated: %v", ps)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// return_to on GET /auth/{id} survives the round trip in the sealed flow
// cookie and is re-validated before the final redirect; anything that is not
// a same-origin path lands on /app (WU-603).
func TestBeginReturnToRoundTrip(t *testing.T) {
	h := newHarness(t)
	srv := oidctest.New(t)
	h.insert(oidcRow("corp", "generic", srv))
	cases := map[string]string{
		"/app/org/o1/settings?tab=sso": "/app/org/o1/settings?tab=sso",
		"//evil.example/app":           "/app",
		"https://evil.example/":        "/app",
		"/\\evil.example":              "/app",
		"/%2F%2Fevil.example":          "/app",
		"javascript:alert(1)":          "/app",
		"":                             "/app",
	}
	for rt, want := range cases {
		srv.SetUser(oidctest.User{Subject: "rt-sub", Email: "rt@example.com", EmailVerified: true})
		u := h.app.URL + "/auth/corp"
		if rt != "" {
			u += "?return_to=" + url.QueryEscape(rt)
		}
		steps, err := oidctest.NewBrowser(t).Follow(u, 6, nil)
		if err != nil {
			t.Fatalf("%q: %v", rt, err)
		}
		end := steps[len(steps)-1]
		if end.URL != h.app.URL+want || end.Status != http.StatusOK {
			t.Errorf("return_to %q landed on %s (%d), want %s", rt, end.URL, end.Status, want)
		}
	}
}
