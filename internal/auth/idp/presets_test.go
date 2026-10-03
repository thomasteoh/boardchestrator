package idp

import (
	"slices"
	"strings"
	"testing"
)

func TestPresetIDsCoverEveryPreset(t *testing.T) {
	if len(PresetIDs) != len(presets) {
		t.Fatalf("PresetIDs has %d entries, presets %d", len(PresetIDs), len(presets))
	}
	for _, id := range PresetIDs {
		p, ok := LookupPreset(id)
		if !ok || p.ID != id {
			t.Errorf("preset %q missing or misnamed", id)
		}
		if p.DisplayName == "" || p.DocsURL == "" || len(p.Scopes) == 0 {
			t.Errorf("preset %q incomplete: %+v", id, p)
		}
		if p.Kind == KindOIDC && (!slices.Contains(p.Scopes, "openid") || p.Claims.Email == "" || p.Claims.Name == "") {
			t.Errorf("OIDC preset %q lacks openid scope or core claims: %+v", id, p)
		}
	}
	if p, ok := LookupPreset(""); !ok || p.ID != "generic" {
		t.Errorf(`LookupPreset("") = %v, %v`, p.ID, ok)
	}
	if _, ok := LookupPreset("nope"); ok {
		t.Error("unknown preset found")
	}
}

// Per-preset issuer template expansion, scopes, claim map and trust default.
func TestPresetCatalogue(t *testing.T) {
	std := ClaimMap{Email: "email", EmailVerified: "email_verified", Name: "name", Picture: "picture"}
	withG := func(g string) ClaimMap { m := std; m.Groups = g; return m }
	cases := []struct {
		id         string
		params     map[string]string
		issuer     string
		scopes     string
		claims     ClaimMap
		trust      bool
		logout     bool
		kind       string
		missingErr bool // expanding with no params fails
	}{
		{id: "google", issuer: "https://accounts.google.com", scopes: "openid email profile", claims: std, trust: true, kind: KindOIDC},
		{id: "microsoft", params: map[string]string{"tenant": "organizations"},
			issuer: "https://login.microsoftonline.com/organizations/v2.0", scopes: "openid email profile",
			claims: ClaimMap{Email: "email", Name: "name", Groups: "groups"}, logout: true, kind: KindOIDC, missingErr: true},
		{id: "gitlab", issuer: "https://gitlab.com", scopes: "openid email profile", claims: withG("groups_direct"), trust: true, kind: KindOIDC},
		{id: "okta", params: map[string]string{"domain": "example.okta.com"}, issuer: "https://example.okta.com",
			scopes: "openid email profile groups", claims: withG("groups"), logout: true, kind: KindOIDC, missingErr: true},
		{id: "auth0", params: map[string]string{"domain": "example.au.auth0.com"}, issuer: "https://example.au.auth0.com/",
			scopes: "openid email profile", claims: std, logout: true, kind: KindOIDC, missingErr: true},
		{id: "keycloak", params: map[string]string{"base_url": "https://sso.example.com/", "realm": "staff"},
			issuer: "https://sso.example.com/realms/staff", scopes: "openid email profile", claims: withG("groups"),
			logout: true, kind: KindOIDC, missingErr: true},
		{id: "zitadel", params: map[string]string{"domain": "example.zitadel.cloud"}, issuer: "https://example.zitadel.cloud",
			scopes: "openid email profile urn:zitadel:iam:org:project:roles",
			claims: withG("urn:zitadel:iam:org:project:roles"), logout: true, kind: KindOIDC, missingErr: true},
		{id: "authentik", params: map[string]string{"base_url": "https://auth.example.com", "slug": "boardchestrator"},
			issuer: "https://auth.example.com/application/o/boardchestrator/", scopes: "openid email profile",
			claims: withG("groups"), logout: true, kind: KindOIDC, missingErr: true},
		{id: "generic", params: map[string]string{"issuer": "https://idp.example.com/tenant/"},
			issuer: "https://idp.example.com/tenant/", scopes: "openid email profile", claims: withG("groups"),
			logout: true, kind: KindOIDC, missingErr: true},
		{id: "github", issuer: "https://github.com", scopes: "read:user user:email", trust: true, kind: KindGitHub},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			p, ok := LookupPreset(tc.id)
			if !ok {
				t.Fatal("missing")
			}
			got, err := p.ExpandIssuer(tc.params)
			if err != nil || got != tc.issuer {
				t.Errorf("issuer = %q, %v; want %q", got, err, tc.issuer)
			}
			if _, err := p.ExpandIssuer(nil); (err != nil) != tc.missingErr {
				t.Errorf("expand without params: err=%v, want error %v", err, tc.missingErr)
			}
			if s := strings.Join(p.Scopes, " "); s != tc.scopes {
				t.Errorf("scopes = %q", s)
			}
			if p.Claims != tc.claims {
				t.Errorf("claims = %+v", p.Claims)
			}
			if p.TrustEmail != tc.trust || p.SupportsLogout != tc.logout || p.Kind != tc.kind {
				t.Errorf("trust=%v logout=%v kind=%s", p.TrustEmail, p.SupportsLogout, p.Kind)
			}
		})
	}
}

func TestExpandIssuerRejectsBadValues(t *testing.T) {
	kc, _ := LookupPreset("keycloak")
	for _, params := range []map[string]string{
		{"base_url": "http://sso.example.com", "realm": "x"}, // plain http, not loopback
		{"base_url": "https://sso.example.com", "realm": "x?y"},
		{"base_url": "sso.example.com", "realm": "x"}, // not absolute
		{"base_url": "https://sso.example.com", "realm": "{realm}"},
	} {
		if iss, err := kc.ExpandIssuer(params); err == nil {
			t.Errorf("%v expanded to %q", params, iss)
		}
	}
	if iss, err := kc.ExpandIssuer(map[string]string{"base_url": "http://127.0.0.1:8081", "realm": "dev"}); err != nil {
		t.Errorf("loopback http refused: %q %v", iss, err)
	}
}

func TestEntraTenant(t *testing.T) {
	for issuer, want := range map[string]struct {
		tenant string
		multi  bool
	}{
		"https://login.microsoftonline.com/organizations/v2.0": {"organizations", true},
		"https://login.microsoftonline.com/common/v2.0":        {"common", true},
		"https://login.microsoftonline.com/consumers/v2.0":     {"consumers", true},
		"https://login.microsoftonline.com/1234-abcd/v2.0":     {"1234-abcd", false},
		"https://login.microsoftonline.com/1234-abcd":          {"", false},
	} {
		tenant, multi := entraTenant(issuer)
		if tenant != want.tenant || multi != want.multi {
			t.Errorf("%s: %q %v", issuer, tenant, multi)
		}
	}
}

func TestValidateID(t *testing.T) {
	for _, ok := range []string{"google", "corp-sso", "a1"} {
		if err := ValidateID(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Corp", "corp_sso", "-x", "logout", "saml", "a/b", strings.Repeat("a", 64)} {
		if ValidateID(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
