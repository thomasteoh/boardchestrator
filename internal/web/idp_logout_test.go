package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// WU-609: the provider forms show the sign-out URIs to register and the
// "Sign out of the identity provider too" setting, defaulting to the
// preset's logout support, and saving stores it.
func TestIdPFormIdPLogoutSetting(t *testing.T) {
	h := newIdPWeb(t)
	admin := h.session("u-admin")
	idpLogout := func(id string) int {
		t.Helper()
		var v int
		if err := h.db.QueryRow(`SELECT idp_logout FROM auth_providers WHERE id=?`, id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	page := h.get("/admin/identity-providers/new?preset=keycloak", &admin).Body.String()
	for _, want := range []string{
		idpTestBase + "/login?signed_out=1",
		idpTestBase + "/auth/oidc/your-id/backchannel-logout",
		"Sign out of the identity provider too",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("new keycloak form lacks %q", want)
		}
	}
	if !strings.Contains(page, `name="idp_logout" value="1" checked`) {
		t.Error("keycloak (supports logout) should default to IdP sign-out on")
	}
	if page := h.get("/admin/identity-providers/new?preset=google", &admin).Body.String(); strings.Contains(page, `name="idp_logout" value="1" checked`) {
		t.Error("google (no end_session_endpoint) should default to IdP sign-out off")
	}
	if page := h.get("/admin/identity-providers/new?preset=github", &admin).Body.String(); strings.Contains(page, "idp_logout") || strings.Contains(page, "backchannel-logout") {
		t.Error("GitHub form offers IdP sign-out")
	}

	form := url.Values{
		"id": {"corp"}, "preset": {"keycloak"}, "param_base_url": {"https://sso.example.com"},
		"param_realm": {"staff"}, "client_id": {"bc"}, "client_secret": {idpTestSecret},
		"idp_logout": {"1"}, "enabled": {"1"},
	}
	if rec := h.post("/admin/identity-providers", &admin, form); rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if idpLogout("corp") != 1 {
		t.Error("idp_logout not stored on")
	}
	edit := h.get("/admin/identity-providers/corp/edit", &admin).Body.String()
	if !strings.Contains(edit, idpTestBase+"/auth/oidc/corp/backchannel-logout") || !strings.Contains(edit, `name="idp_logout" value="1" checked`) {
		t.Error("edit form: back-channel URL or setting missing")
	}
	form.Del("idp_logout")
	form.Del("enabled")
	if rec := h.post("/admin/identity-providers/corp/update", &admin, form); rec.Code != http.StatusSeeOther {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if idpLogout("corp") != 0 {
		t.Error("unchecking IdP sign-out did not store off")
	}

	// The organisation form shows the same URIs with the org's id prefix.
	owner := h.session("u-owner")
	page = h.get("/app/org/org-a/settings/sso/providers/new?preset=okta", &owner).Body.String()
	if !strings.Contains(page, idpTestBase+"/auth/oidc/a-your-id/backchannel-logout") ||
		!strings.Contains(page, idpTestBase+"/login?signed_out=1") ||
		!strings.Contains(page, `name="idp_logout" value="1" checked`) {
		t.Error("org provider form lacks the sign-out URIs or setting")
	}
}
