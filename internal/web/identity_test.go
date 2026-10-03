package web

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/idp"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/perm"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

const (
	idpTestSessionSecret = "0123456789abcdef0123456789abcdef"
	idpTestBase          = "https://bc.example.com"
	idpTestSecret        = "Sup3r-Secret-Client-Value"
)

var idpTestKey = tenant.PadKey("test-secret-key-for-identity")

type idpWeb struct {
	t      *testing.T
	db     *sql.DB
	router http.Handler
	reg    *idp.Registry
	store  *auth.SessionStore
}

// newIdPWeb mounts the web routes behind the production middleware order
// (CSP → session → CSRF) with the real permission engine.
func newIdPWeb(t *testing.T) *idpWeb {
	t.Helper()
	d := dbtest.New(t)
	for _, q := range []string{
		`INSERT INTO users (id, email) VALUES ('u-admin','admin@example.com'),('u-plain','plain@example.com'),('u-owner','owner@example.com')`,
		`INSERT INTO orgs (id, name, slug) VALUES ('org-a','A','a')`,
		`INSERT INTO roles (id, org_id, name, is_system, grants_json) VALUES ('r-owner','org-a','Owner',0,'["*"]')`,
		`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id)
		 VALUES ('m1','00000000000000000000000000000000','u-admin','user','org','00000000000000000000000000000000','00000000000000000000000000000000'),
		        ('m2','org-a','u-owner','user','org','org-a','r-owner')`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	SetDispatcher(action.New(d,
		action.WithScopeResolver(action.NewDBScopeResolver(d)),
		action.WithPermissionChecker(perm.NewCheckerAdapter(d)),
		action.WithSecretKey(idpTestKey),
	))
	reg := idp.New(idp.Options{DB: d, EncKey: idpTestKey, BaseURL: idpTestBase})
	SetIdentity(idpTestBase, reg)
	store := auth.NewSessionStore(d)
	r := chi.NewRouter()
	r.Use(auth.CSP())
	sc := auth.SessionConfig{Store: store, Secret: idpTestSessionSecret}
	r.Use(sc.Session())
	r.Use(sc.CSRF())
	Routes(r)
	return &idpWeb{t: t, db: d, router: r, reg: reg, store: store}
}

type idpSession struct{ raw, csrf string }

func (h *idpWeb) session(userID string) idpSession {
	h.t.Helper()
	raw, sess, err := h.store.Create(context.Background(), userID, "", "")
	if err != nil {
		h.t.Fatal(err)
	}
	return idpSession{raw: raw, csrf: auth.CSRFToken(idpTestSessionSecret, sess.TokenHash)}
}

func (h *idpWeb) get(path string, s *idpSession) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if s != nil {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: s.raw})
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func (h *idpWeb) post(path string, s *idpSession, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if s != nil && s.csrf != "" {
		form.Set(auth.CSRFFormField, s.csrf)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s != nil {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: s.raw})
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func (h *idpWeb) insert(id, preset, issuer string, enabled, position int, orgID string) {
	h.t.Helper()
	var org any
	if orgID != "" {
		org = orgID
	}
	if _, err := h.db.Exec(`INSERT INTO auth_providers (id, org_id, kind, preset, display_name, enabled, issuer, client_id, position)
		VALUES (?, ?, 'oidc', ?, ?, ?, ?, 'c', ?)`, id, org, preset, "Name "+id, enabled, issuer, position); err != nil {
		h.t.Fatal(err)
	}
	h.reg.Invalidate()
}

var loginHrefRe = regexp.MustCompile(`href="(/auth/[^"]*)"`)

func TestLoginPageListsEnabledPlatformProvidersInOrder(t *testing.T) {
	h := newIdPWeb(t)
	h.insert("zeta", "google", "https://accounts.google.com", 1, 20, "")
	h.insert("alpha", "keycloak", "https://sso.example.com/realms/x", 1, 10, "")
	h.insert("off", "generic", "https://off.example.com", 0, 5, "")
	h.insert("orgsso", "generic", "https://org.example.com", 1, 1, "org-a")

	rec := h.get("/login", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login: %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	body := rec.Body.String()
	var hrefs []string
	for _, m := range loginHrefRe.FindAllStringSubmatch(body, -1) {
		hrefs = append(hrefs, m[1])
	}
	if strings.Join(hrefs, " ") != "/auth/alpha /auth/zeta" {
		t.Errorf("provider links = %v, want alpha then zeta only", hrefs)
	}
	if !strings.Contains(body, "Continue with Name alpha") || strings.Contains(body, "Name off") || strings.Contains(body, "Name orgsso") {
		t.Error("login page shows the wrong providers")
	}
	if !strings.Contains(body, `bc-idp-mark-keycloak`) {
		t.Error("preset mark missing")
	}
	// No inline script beyond the layout's nonced ones.
	for _, m := range regexp.MustCompile(`<script[^>]*>`).FindAllString(body, -1) {
		if !strings.Contains(m, "nonce=") {
			t.Errorf("script without nonce: %s", m)
		}
	}

	// return_to is carried to /auth/{id}; unsafe values are dropped.
	body = h.get("/login?return_to="+url.QueryEscape("/app/org/a/settings"), nil).Body.String()
	if !strings.Contains(body, `href="/auth/alpha?return_to=%2Fapp%2Forg%2Fa%2Fsettings"`) {
		t.Errorf("return_to not carried: %v", loginHrefRe.FindAllString(body, -1))
	}
	for _, evil := range []string{"//evil.example", "https://evil.example", "/\\evil.example", "/%2F%2Fevil.example", "javascript:alert(1)", "/%5Cevil.example"} {
		body = h.get("/login?return_to="+url.QueryEscape(evil), nil).Body.String()
		if strings.Contains(body, "evil") {
			t.Errorf("return_to %q reflected into the page", evil)
		}
	}
}

func TestLoginPageNoProviders(t *testing.T) {
	h := newIdPWeb(t)
	body := h.get("/login", nil).Body.String()
	if !strings.Contains(body, "No sign-in methods are set up") || loginHrefRe.MatchString(body) {
		t.Error("empty-instance message missing")
	}
}

func TestLoginPageSignedInRedirects(t *testing.T) {
	h := newIdPWeb(t)
	s := h.session("u-plain")
	cases := map[string]string{
		"/login":                              "/app",
		"/login?return_to=%2Fapp%2Fsearch":    "/app/search",
		"/login?return_to=%2F%2Fevil.example": "/app",
		"/login?return_to=https%3A%2F%2Fevil": "/app",
		"/login?return_to=%2F%5Cevil.example": "/app",
	}
	for path, want := range cases {
		rec := h.get(path, &s)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
			t.Errorf("%s signed in: %d → %q, want %q", path, rec.Code, rec.Header().Get("Location"), want)
		}
	}
}

func TestLoginPageBanners(t *testing.T) {
	h := newIdPWeb(t)
	body := h.get("/login?error=0A1B2C3D4E", nil).Body.String()
	if !strings.Contains(body, "couldn't sign you in") || !strings.Contains(body, "<code>0A1B2C3D4E</code>") {
		t.Error("error banner with reference missing")
	}
	body = h.get("/login?error="+url.QueryEscape(`<script>alert(1)</script>`), nil).Body.String()
	if !strings.Contains(body, "couldn't sign you in") || strings.Contains(body, "alert(1)") {
		t.Error("error banner must not reflect a non-reference value")
	}
	body = h.get("/login?signed_out=1", nil).Body.String()
	if !strings.Contains(body, "You've been signed out.") {
		t.Error("signed-out banner missing")
	}
	if strings.Contains(h.get("/login", nil).Body.String(), "bc-alert") {
		t.Error("banner shown without a reason")
	}
}

func TestLandingAndFailurePagePointToLogin(t *testing.T) {
	h := newIdPWeb(t)
	body := h.get("/", nil).Body.String()
	if !strings.Contains(body, `href="/login"`) || strings.Contains(body, `href="/auth/github"`) {
		t.Error("landing page should link to /login")
	}
	rec := httptest.NewRecorder()
	RenderLoginFailedPage(rec, httptest.NewRequest(http.MethodGet, "/auth/x/callback", nil), http.StatusForbidden, "Nope.", "ABCDEF0123")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `href="/login?error=ABCDEF0123"`) ||
		!strings.Contains(rec.Body.String(), "Back to sign in") {
		t.Errorf("failure page: %d %s", rec.Code, rec.Body.String())
	}
}

func TestIdPAdminPagesAccess(t *testing.T) {
	h := newIdPWeb(t)
	h.insert("alpha", "keycloak", "https://sso.example.com/realms/staff", 1, 10, "")
	pages := []string{"/admin/identity-providers", "/admin/identity-providers/new?preset=keycloak", "/admin/identity-providers/alpha/edit"}

	admin := h.session("u-admin")
	for _, p := range pages {
		rec := h.get(p, &admin)
		if rec.Code != http.StatusOK {
			t.Errorf("admin GET %s: %d", p, rec.Code)
		}
	}
	for _, uid := range []string{"u-plain", "u-owner"} {
		s := h.session(uid)
		for _, p := range pages {
			if rec := h.get(p, &s); rec.Code != http.StatusForbidden {
				t.Errorf("%s GET %s: %d, want 403", uid, p, rec.Code)
			}
		}
		if rec := h.post("/admin/identity-providers/alpha/disable", &s, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s disable: %d, want 403", uid, rec.Code)
		}
	}
	rec := h.get("/admin/identity-providers", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?return_to=%2Fadmin%2Fidentity-providers" {
		t.Errorf("anonymous GET: %d → %q", rec.Code, rec.Header().Get("Location"))
	}

	list := h.get("/admin/identity-providers", &admin).Body.String()
	for _, want := range []string{"Name alpha", "Keycloak", "Enabled", "Admin UI", `action="/admin/identity-providers/alpha/disable"`, "/admin/identity-providers/new?preset=github"} {
		if !strings.Contains(list, want) {
			t.Errorf("list page missing %q", want)
		}
	}
	form := h.get("/admin/identity-providers/new?preset=keycloak", &admin).Body.String()
	for _, want := range []string{`name="param_base_url"`, `name="param_realm"`, idpTestBase + "/auth/your-id/callback", "Test discovery", "take over", `name="claim_groups"`} {
		if !strings.Contains(form, want) {
			t.Errorf("keycloak form missing %q", want)
		}
	}
	if strings.Contains(form, `name="param_tenant"`) || strings.Contains(form, `name="allowed_tenants"`) {
		t.Error("keycloak form shows Microsoft-only fields")
	}
	ms := h.get("/admin/identity-providers/new?preset=microsoft", &admin).Body.String()
	if !strings.Contains(ms, `name="param_tenant"`) || !strings.Contains(ms, `name="allowed_tenants"`) {
		t.Error("microsoft form missing tenant fields")
	}
	edit := h.get("/admin/identity-providers/alpha/edit", &admin).Body.String()
	if !strings.Contains(edit, idpTestBase+"/auth/alpha/callback") || !strings.Contains(edit, `value="staff"`) {
		t.Error("edit page missing callback URL or parsed realm")
	}
}

func TestIdPAdminCreateEditFlow(t *testing.T) {
	h := newIdPWeb(t)
	admin := h.session("u-admin")
	form := url.Values{
		"id": {"corp"}, "preset": {"keycloak"}, "display_name": {"Corp SSO"},
		"param_base_url": {"https://sso.example.com"}, "param_realm": {"staff"},
		"client_id": {"bc"}, "client_secret": {idpTestSecret}, "claim_groups": {"realm_access.roles"},
		"trust_email": {"1"}, "enabled": {"1"},
	}
	// No CSRF token → refused by the middleware.
	if rec := h.post("/admin/identity-providers", &idpSession{raw: admin.raw}, form); rec.Code != http.StatusForbidden {
		t.Fatalf("create without CSRF: %d", rec.Code)
	}
	// A non-admin with a valid token is refused by the action.
	plain := h.session("u-plain")
	if rec := h.post("/admin/identity-providers", &plain, form); rec.Code != http.StatusForbidden {
		t.Fatalf("create as non-admin: %d", rec.Code)
	}
	rec := h.post("/admin/identity-providers", &admin, form)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/identity-providers?notice=created" {
		t.Fatalf("create: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	var issuer, claims string
	var trust, enabled int
	if err := h.db.QueryRow(`SELECT issuer, claim_map_json, trust_email, enabled FROM auth_providers WHERE id='corp'`).Scan(&issuer, &claims, &trust, &enabled); err != nil {
		t.Fatal(err)
	}
	if issuer != "https://sso.example.com/realms/staff" || claims != `{"groups":"realm_access.roles"}` || trust != 1 || enabled != 1 {
		t.Errorf("stored row: %s %s %d %d", issuer, claims, trust, enabled)
	}
	// The registry (and so /login) sees it without a restart; here the
	// invalidation comes from the bus in production, so poke it directly.
	h.reg.Invalidate()
	if !strings.Contains(h.get("/login", nil).Body.String(), `href="/auth/corp"`) {
		t.Error("new provider not on /login")
	}

	for _, page := range []string{"/admin/identity-providers?notice=created", "/admin/identity-providers/corp/edit"} {
		body := h.get(page, &admin).Body.String()
		if strings.Contains(body, idpTestSecret) {
			t.Errorf("%s leaks the client secret", page)
		}
	}
	if !strings.Contains(h.get("/admin/identity-providers/corp/edit", &admin).Body.String(), "A secret is set") {
		t.Error("edit page should say a secret is set")
	}

	// Invalid update re-renders with our message and keeps the input.
	bad := url.Values{"preset": {"keycloak"}, "param_base_url": {"http://sso.example.com"}, "param_realm": {"staff"}, "client_id": {"bc"}}
	rec = h.post("/admin/identity-providers/corp/update", &admin, bad)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "must use https") {
		t.Errorf("invalid update: %d", rec.Code)
	}
	// Valid update with a blank secret keeps it.
	good := url.Values{"preset": {"keycloak"}, "param_base_url": {"https://sso.example.com"}, "param_realm": {"staff2"}, "client_id": {"bc"}, "display_name": {"Staff"}}
	if rec = h.post("/admin/identity-providers/corp/update", &admin, good); rec.Code != http.StatusSeeOther {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	var enc string
	_ = h.db.QueryRow(`SELECT client_secret_enc, issuer FROM auth_providers WHERE id='corp'`).Scan(&enc, &issuer)
	if plain, err := tenant.Decrypt(idpTestKey, enc); err != nil || plain != idpTestSecret || issuer != "https://sso.example.com/realms/staff2" {
		t.Errorf("after update: issuer %s secret kept=%v", issuer, plain == idpTestSecret)
	}

	if rec = h.post("/admin/identity-providers/corp/disable", &admin, nil); rec.Code != http.StatusSeeOther {
		t.Errorf("disable: %d", rec.Code)
	}
	if rec = h.post("/admin/identity-providers/corp/delete", &admin, nil); rec.Code != http.StatusSeeOther {
		t.Errorf("delete: %d", rec.Code)
	}
}

func TestIdPAdminEnvRowReadOnly(t *testing.T) {
	h := newIdPWeb(t)
	if _, err := h.db.Exec(`INSERT INTO auth_providers (id, kind, preset, display_name, managed_by, issuer, client_id)
		VALUES ('google','oidc','google','Google','env','https://accounts.google.com','g')`); err != nil {
		t.Fatal(err)
	}
	admin := h.session("u-admin")
	list := h.get("/admin/identity-providers", &admin).Body.String()
	if !strings.Contains(list, "Environment") || strings.Contains(list, `action="/admin/identity-providers/google/disable"`) {
		t.Error("env row should be listed without controls")
	}
	edit := h.get("/admin/identity-providers/google/edit", &admin).Body.String()
	if !strings.Contains(edit, "configured by environment variables") || !strings.Contains(edit, "<fieldset class=\"bc-fieldset\" disabled") || strings.Contains(edit, "Save changes") {
		t.Error("env row edit page should be read-only")
	}
	rec := h.post("/admin/identity-providers/google/disable", &admin, nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "environment variables") {
		t.Errorf("disable env row: %d", rec.Code)
	}
}

func TestIdPAdminDiscoverFragment(t *testing.T) {
	h := newIdPWeb(t)
	admin := h.session("u-admin")
	rec := h.post("/admin/identity-providers/discover", &admin, url.Values{"preset": {"generic"}, "param_issuer": {"https://169.254.169.254/x"}})
	body, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK || !strings.Contains(string(body), "Reference: <code>") || strings.Contains(string(body), "not allowed") {
		t.Errorf("discover fragment: %d %s", rec.Code, body)
	}
	plain := h.session("u-plain")
	if rec := h.post("/admin/identity-providers/discover", &plain, url.Values{"preset": {"generic"}, "param_issuer": {"https://idp.example.com"}}); rec.Code != http.StatusForbidden {
		t.Errorf("non-admin discover: %d", rec.Code)
	}
}
