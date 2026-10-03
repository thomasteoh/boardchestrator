package idp

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/thomasteoh/boardchestrator/internal/auth"
)

// GoogleIssuer is Google's OIDC issuer.
const GoogleIssuer = "https://accounts.google.com"

// DiscoveryTTL is how long a discovered provider is cached (SPEC §7.1).
const DiscoveryTTL = time.Hour

// OIDCConfig configures the generic OpenID Connect connector that every
// preset except GitHub runs on.
type OIDCConfig struct {
	ID           string // provider id, e.g. "google"
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL is the absolute callback URL registered with the IdP.
	RedirectURL string
	Scopes      []string // default: openid email profile
	// Claims maps assertion fields to claims; zero value = standard claims.
	Claims ClaimMap
	Policy auth.ResolvePolicy
	// EntraMultiTenant: the issuer is a Microsoft organizations/common/
	// consumers endpoint. go-oidc's issuer checks are skipped and the token's
	// iss must instead be the issuer with the pseudo-tenant replaced by the
	// token's own tid. AllowedTenants, when non-empty, restricts tid.
	EntraMultiTenant bool
	AllowedTenants   []string
	// IdPLogout: logout continues to the provider's end_session_endpoint
	// when discovery publishes one (SPEC §7.6).
	IdPLogout bool
	// Client is the IdP HTTP client; nil = NewIdPClient(nil).
	Client *http.Client
}

// OIDCConnector signs users in with the authorisation-code flow, PKCE (S256)
// and a nonce, verifying the ID token's signature, iss, aud and exp with
// go-oidc. Discovery is lazy and cached for DiscoveryTTL, so an unreachable
// IdP fails only its own logins, never startup.
type OIDCConnector struct {
	cfg OIDCConfig

	mu        sync.Mutex
	provider  *oidc.Provider
	fetchedAt time.Time
}

// NewOIDCConnector builds a connector; no network traffic happens until the
// first Begin.
func NewOIDCConnector(cfg OIDCConfig) *OIDCConnector {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	if cfg.Claims == (ClaimMap{}) {
		cfg.Claims = standardClaims
	}
	if cfg.Client == nil {
		cfg.Client = NewIdPClient(nil)
	}
	return &OIDCConnector{cfg: cfg}
}

// NewGoogleConnector is the Google preset with a fixed trusted, open sign-up
// policy: issuer accounts.google.com, or issuer when non-empty (tests point it
// at oidctest). Production wiring builds Google from its auth_providers row.
func NewGoogleConnector(issuer, clientID, clientSecret, baseURL string, client *http.Client) *OIDCConnector {
	if issuer == "" {
		issuer = GoogleIssuer
	}
	return NewOIDCConnector(OIDCConfig{
		ID:           "google",
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  CallbackURL(baseURL, "google"),
		Policy:       auth.ResolvePolicy{TrustEmail: true, AllowSignup: true},
		Client:       client,
	})
}

// CallbackURL is the redirect URI registered with a provider.
func CallbackURL(baseURL, providerID string) string {
	return strings.TrimRight(baseURL, "/") + "/auth/" + providerID + "/callback"
}

func (c *OIDCConnector) ID() string                 { return c.cfg.ID }
func (c *OIDCConnector) AuthMethod() string         { return auth.AuthMethodOIDC }
func (c *OIDCConnector) Policy() auth.ResolvePolicy { return c.cfg.Policy }

func (c *OIDCConnector) clientCtx(ctx context.Context) context.Context {
	// x/oauth2 reads the client from oauth2.HTTPClient; go-oidc from its own
	// key. They share the same *http.Client.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.cfg.Client)
	return oidc.ClientContext(ctx, c.cfg.Client)
}

func (c *OIDCConnector) discover(ctx context.Context) (*oidc.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil && time.Since(c.fetchedAt) < DiscoveryTTL {
		return c.provider, nil
	}
	// The provider's key set keeps this context for later JWKS refreshes, so
	// it must outlive the request.
	dctx := c.clientCtx(context.WithoutCancel(ctx))
	if c.cfg.EntraMultiTenant {
		// Entra's multi-tenant discovery document advertises the templated
		// issuer ".../{tenantid}/v2.0", not the URL it was fetched from.
		dctx = oidc.InsecureIssuerURLContext(dctx, c.cfg.Issuer)
	}
	p, err := oidc.NewProvider(dctx, c.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc %s: discovery: %w", c.cfg.ID, err)
	}
	c.provider, c.fetchedAt = p, time.Now()
	return p, nil
}

func (c *OIDCConnector) oauth2Config(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		Scopes:       c.cfg.Scopes,
		RedirectURL:  c.cfg.RedirectURL,
	}
}

// Begin returns the IdP authorisation URL carrying state, nonce and the PKCE
// S256 challenge from flow.
func (c *OIDCConnector) Begin(ctx context.Context, flow *auth.Flow) (string, error) {
	p, err := c.discover(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{
		oidc.Nonce(flow.Nonce),
		oauth2.S256ChallengeOption(flow.PKCEVerifier),
	}
	if flow.LoginHint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", flow.LoginHint))
	}
	return c.oauth2Config(p).AuthCodeURL(flow.State, opts...), nil
}

// Complete exchanges the code (with the PKCE verifier), verifies the ID token
// and its nonce, and returns the assertion. The handler has already checked
// state against the flow cookie.
func (c *OIDCConnector) Complete(ctx context.Context, r *http.Request, flow *auth.Flow) (*auth.Assertion, error) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return nil, fmt.Errorf("oidc %s: authorisation error %q", c.cfg.ID, e)
	}
	code := q.Get("code")
	if code == "" {
		return nil, fmt.Errorf("oidc %s: no code", c.cfg.ID)
	}
	p, err := c.discover(ctx)
	if err != nil {
		return nil, err
	}
	cctx := c.clientCtx(ctx)
	tok, err := c.oauth2Config(p).Exchange(cctx, code, oauth2.VerifierOption(flow.PKCEVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc %s: token exchange: %w", c.cfg.ID, err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, fmt.Errorf("oidc %s: no id_token", c.cfg.ID)
	}
	vcfg := &oidc.Config{ClientID: c.cfg.ClientID, SkipIssuerCheck: c.cfg.EntraMultiTenant}
	idt, err := p.Verifier(vcfg).Verify(cctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("oidc %s: verify id_token: %w", c.cfg.ID, err)
	}
	if idt.Nonce == "" || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(flow.Nonce)) != 1 {
		return nil, fmt.Errorf("oidc %s: nonce mismatch", c.cfg.ID)
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc %s: id_token claims: %w", c.cfg.ID, err)
	}
	if c.cfg.EntraMultiTenant {
		if err := c.checkEntraIssuer(idt.Issuer, claims); err != nil {
			return nil, err
		}
	}

	// Userinfo only fills claims the ID token lacks, and must be about the
	// same subject.
	cm := c.cfg.Claims
	if claimString(claims, cm.Email) == "" && p.UserInfoEndpoint() != "" {
		ui, err := p.UserInfo(cctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return nil, fmt.Errorf("oidc %s: userinfo: %w", c.cfg.ID, err)
		}
		if ui.Subject != idt.Subject {
			return nil, fmt.Errorf("oidc %s: userinfo subject mismatch", c.cfg.ID)
		}
		uc := map[string]any{}
		if err := ui.Claims(&uc); err != nil {
			return nil, fmt.Errorf("oidc %s: userinfo claims: %w", c.cfg.ID, err)
		}
		for k, v := range uc {
			if _, ok := claims[k]; !ok {
				claims[k] = v
			}
		}
	}

	a := &auth.Assertion{
		ProviderID: c.cfg.ID,
		Subject:    idt.Subject,
		Email:      claimString(claims, cm.Email),
		Name:       claimString(claims, cm.Name),
		Picture:    claimString(claims, cm.Picture),
		SID:        claimString(claims, "sid"),
		IDTokenRaw: rawID,
		RawClaims:  claims,
	}
	// An unmapped email_verified means this IdP never vouches for the email.
	if cm.EmailVerified != "" {
		a.EmailVerified = claimBool(claims, cm.EmailVerified)
	}
	if cm.Groups != "" {
		a.Groups = ClaimGroups(claims, cm.Groups)
		a.GroupsClaim = cm.Groups
	}
	return a, nil
}

// checkEntraIssuer enforces SPEC §7.1's multi-tenant rule: iss must be the
// configured issuer with the pseudo-tenant replaced by the token's tid, and
// tid must be allowed.
func (c *OIDCConnector) checkEntraIssuer(iss string, claims map[string]any) error {
	tid := claimString(claims, "tid")
	if tid == "" || strings.ContainsAny(tid, "/?#") {
		return fmt.Errorf("oidc %s: multi-tenant token without a valid tid", c.cfg.ID)
	}
	pseudo, _ := entraTenant(c.cfg.Issuer)
	want := strings.Replace(c.cfg.Issuer, "/"+pseudo+"/", "/"+tid+"/", 1)
	if subtle.ConstantTimeCompare([]byte(iss), []byte(want)) != 1 {
		return fmt.Errorf("oidc %s: issuer %q does not match tenant %q", c.cfg.ID, iss, tid)
	}
	if len(c.cfg.AllowedTenants) > 0 && !slices.Contains(c.cfg.AllowedTenants, tid) {
		return fmt.Errorf("oidc %s: tenant %q not allowed", c.cfg.ID, tid)
	}
	return nil
}
