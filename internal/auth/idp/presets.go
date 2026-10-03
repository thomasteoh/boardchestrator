package idp

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Provider kinds (auth_providers.kind).
const (
	KindOIDC   = "oidc"
	KindGitHub = "github"
	KindSAML   = "saml"
)

// Preset is a provider template (SPEC §7.1). Presets are data: every OIDC
// preset runs through the same generic connector, configured by these fields.
type Preset struct {
	ID          string
	DisplayName string
	Kind        string
	// IssuerTemplate is the issuer URL with {param} placeholders, filled from
	// Params by ExpandIssuer. GitHub's "issuer" is its web base URL.
	IssuerTemplate string
	// Params are the placeholders IssuerTemplate needs, in prompt order.
	Params []PresetParam
	Scopes []string
	Claims ClaimMap
	// TrustEmail is the default for auth_providers.trust_email.
	TrustEmail bool
	// SupportsLogout: the IdP publishes an end_session_endpoint (WU-609).
	SupportsLogout bool
	DocsURL        string
}

// PresetParam is one issuer-template placeholder.
type PresetParam struct {
	Name    string // placeholder name, e.g. "tenant"
	Label   string // admin UI label
	Default string // "" = required
	Help    string
}

// Microsoft Entra multi-tenant pseudo-tenants: the issuer in the token is the
// user's real tenant, so go-oidc's issuer check cannot be used (SPEC §7.1).
var entraMultiTenant = map[string]bool{"organizations": true, "common": true, "consumers": true}

var oidcScopes = []string{"openid", "email", "profile"}

func withGroups(m ClaimMap, groups string) ClaimMap {
	m.Groups = groups
	return m
}

// Presets, keyed by id. The admin UI (WU-603) lists them in PresetIDs order.
var presets = map[string]Preset{
	"google": {
		ID: "google", DisplayName: "Google", Kind: KindOIDC,
		IssuerTemplate: "https://accounts.google.com",
		Scopes:         oidcScopes,
		Claims:         standardClaims,
		TrustEmail:     true,
		DocsURL:        "https://developers.google.com/identity/openid-connect/openid-connect",
	},
	"microsoft": {
		ID: "microsoft", DisplayName: "Microsoft", Kind: KindOIDC,
		IssuerTemplate: "https://login.microsoftonline.com/{tenant}/v2.0",
		Params: []PresetParam{{Name: "tenant", Label: "Tenant ID",
			Help: "Directory (tenant) id, or organizations/common for multi-tenant sign-in"}},
		Scopes: oidcScopes,
		// Entra's email claim is unverified and it emits no email_verified;
		// an admin may map an optional claim such as xms_edov.
		Claims:         ClaimMap{Email: "email", Name: "name", Groups: "groups"},
		SupportsLogout: true,
		DocsURL:        "https://learn.microsoft.com/entra/identity-platform/v2-protocols-oidc",
	},
	"gitlab": {
		ID: "gitlab", DisplayName: "GitLab", Kind: KindOIDC,
		IssuerTemplate: "{base_url}",
		Params:         []PresetParam{{Name: "base_url", Label: "GitLab URL", Default: "https://gitlab.com"}},
		Scopes:         oidcScopes,
		Claims:         withGroups(standardClaims, "groups_direct"),
		TrustEmail:     true,
		DocsURL:        "https://docs.gitlab.com/integration/openid_connect_provider/",
	},
	"okta": {
		ID: "okta", DisplayName: "Okta", Kind: KindOIDC,
		IssuerTemplate: "https://{domain}",
		Params: []PresetParam{{Name: "domain", Label: "Okta domain",
			Help: "e.g. example.okta.com, or example.okta.com/oauth2/default for a custom authorisation server"}},
		Scopes:         []string{"openid", "email", "profile", "groups"},
		Claims:         withGroups(standardClaims, "groups"),
		SupportsLogout: true,
		DocsURL:        "https://developer.okta.com/docs/guides/sign-into-web-app-redirect/",
	},
	"auth0": {
		ID: "auth0", DisplayName: "Auth0", Kind: KindOIDC,
		IssuerTemplate: "https://{domain}/",
		Params:         []PresetParam{{Name: "domain", Label: "Auth0 domain", Help: "e.g. example.au.auth0.com"}},
		Scopes:         oidcScopes,
		// Auth0 groups come from a namespaced custom claim set by an Action.
		Claims:         standardClaims,
		SupportsLogout: true,
		DocsURL:        "https://auth0.com/docs/authenticate/protocols/openid-connect-protocol",
	},
	"keycloak": {
		ID: "keycloak", DisplayName: "Keycloak", Kind: KindOIDC,
		IssuerTemplate: "{base_url}/realms/{realm}",
		Params: []PresetParam{
			{Name: "base_url", Label: "Keycloak URL", Help: "e.g. https://sso.example.com"},
			{Name: "realm", Label: "Realm"},
		},
		Scopes:         oidcScopes,
		Claims:         withGroups(standardClaims, "groups"),
		SupportsLogout: true,
		DocsURL:        "https://www.keycloak.org/docs/latest/server_admin/#_oidc_clients",
	},
	"zitadel": {
		ID: "zitadel", DisplayName: "Zitadel", Kind: KindOIDC,
		IssuerTemplate: "https://{domain}",
		Params:         []PresetParam{{Name: "domain", Label: "Zitadel domain", Help: "e.g. example.zitadel.cloud"}},
		Scopes:         []string{"openid", "email", "profile", "urn:zitadel:iam:org:project:roles"},
		// Project roles arrive as an object keyed by role name.
		Claims:         withGroups(standardClaims, "urn:zitadel:iam:org:project:roles"),
		SupportsLogout: true,
		DocsURL:        "https://zitadel.com/docs/guides/integrate/login/oidc",
	},
	"authentik": {
		ID: "authentik", DisplayName: "authentik", Kind: KindOIDC,
		IssuerTemplate: "{base_url}/application/o/{slug}/",
		Params: []PresetParam{
			{Name: "base_url", Label: "authentik URL", Help: "e.g. https://auth.example.com"},
			{Name: "slug", Label: "Application slug"},
		},
		Scopes:         oidcScopes,
		Claims:         withGroups(standardClaims, "groups"),
		SupportsLogout: true,
		DocsURL:        "https://docs.goauthentik.io/docs/add-secure-apps/providers/oauth2/",
	},
	"generic": {
		ID: "generic", DisplayName: "OpenID Connect", Kind: KindOIDC,
		IssuerTemplate: "{issuer}",
		Params:         []PresetParam{{Name: "issuer", Label: "Issuer URL"}},
		Scopes:         oidcScopes,
		Claims:         withGroups(standardClaims, "groups"),
		SupportsLogout: true,
		DocsURL:        "https://openid.net/specs/openid-connect-discovery-1_0.html",
	},
	"github": {
		ID: "github", DisplayName: "GitHub", Kind: KindGitHub,
		IssuerTemplate: GitHubWebBase,
		Scopes:         []string{"read:user", "user:email"},
		// GitHub is not OIDC; the connector reads /user and /user/emails and
		// only ever asserts a verified primary email.
		TrustEmail: true,
		DocsURL:    "https://docs.github.com/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app",
	},
}

// PresetIDs lists the presets in display order.
var PresetIDs = []string{"google", "microsoft", "github", "gitlab", "okta", "auth0", "keycloak", "zitadel", "authentik", "generic"}

// LookupPreset returns the preset with id ("" = generic).
func LookupPreset(id string) (Preset, bool) {
	if id == "" {
		id = "generic"
	}
	p, ok := presets[id]
	if ok {
		p.Scopes = append([]string(nil), p.Scopes...)
		p.Params = append([]PresetParam(nil), p.Params...)
	}
	return p, ok
}

// ExpandIssuer fills the preset's issuer template from params, applying
// defaults, and validates the result. Trailing slashes on URL-valued params
// are trimmed so "https://sso.example.com/" + "/realms/x" stays well-formed.
func (p Preset) ExpandIssuer(params map[string]string) (string, error) {
	out := p.IssuerTemplate
	for _, pp := range p.Params {
		v := strings.TrimSpace(params[pp.Name])
		if v == "" {
			v = pp.Default
		}
		if v == "" {
			return "", fmt.Errorf("preset %s: %s is required", p.ID, pp.Name)
		}
		if pp.Name != "issuer" {
			v = strings.TrimRight(v, "/")
		}
		if strings.ContainsAny(v, "{}?#") {
			return "", fmt.Errorf("preset %s: invalid %s", p.ID, pp.Name)
		}
		out = strings.ReplaceAll(out, "{"+pp.Name+"}", v)
	}
	if strings.Contains(out, "{") {
		return "", fmt.Errorf("preset %s: unfilled issuer template %q", p.ID, out)
	}
	if err := ValidateIssuer(out); err != nil {
		return "", err
	}
	return out, nil
}

// ValidateIssuer requires an absolute https URL without query or fragment;
// plain http is accepted only for loopback hosts (local IdPs and tests).
func ValidateIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("issuer %q is not an absolute URL", issuer)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("issuer %q must use https", issuer)
}

// entraTenant returns the tenant path segment of a Microsoft issuer
// (https://login.microsoftonline.com/<tenant>/v2.0) and whether it is one of
// the multi-tenant pseudo-tenants.
func entraTenant(issuer string) (tenant string, multi bool) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", false
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) < 2 || segs[len(segs)-1] != "v2.0" {
		return "", false
	}
	tenant = segs[len(segs)-2]
	return tenant, entraMultiTenant[tenant]
}
