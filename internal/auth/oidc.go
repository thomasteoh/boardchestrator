package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// GoogleIssuer is Google's OIDC issuer.
const GoogleIssuer = "https://accounts.google.com"

// discoveryTTL is how long a discovered provider is cached (SPEC §7.1).
const discoveryTTL = time.Hour

// OIDCConfig configures an OpenID Connect connector.
type OIDCConfig struct {
	ID           string // provider id, e.g. "google"
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL is the absolute callback URL registered with the IdP.
	RedirectURL string
	Scopes      []string // default: openid email profile
	Policy      ResolvePolicy
	// Client is the IdP HTTP client; nil = NewIdPClient(nil).
	Client *http.Client
}

// OIDCConnector signs users in with the authorisation-code flow, PKCE (S256)
// and a nonce, verifying the ID token's signature, iss, aud and exp with
// go-oidc. Discovery is lazy and cached, so an unreachable IdP fails only its
// own logins, never startup.
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
	if cfg.Client == nil {
		cfg.Client = NewIdPClient(nil)
	}
	return &OIDCConnector{cfg: cfg}
}

// NewGoogleConnector is the Google preset: issuer accounts.google.com (or
// issuer, when non-empty, so tests can point it at oidctest), trusted for
// email, sign-up allowed (WU-604 makes this configurable).
func NewGoogleConnector(issuer, clientID, clientSecret, baseURL string, client *http.Client) *OIDCConnector {
	if issuer == "" {
		issuer = GoogleIssuer
	}
	return NewOIDCConnector(OIDCConfig{
		ID:           "google",
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  baseURL + "/auth/google/callback",
		Policy:       ResolvePolicy{TrustEmail: true, AllowSignup: true},
		Client:       client,
	})
}

func (c *OIDCConnector) ID() string            { return c.cfg.ID }
func (c *OIDCConnector) AuthMethod() string    { return AuthMethodOIDC }
func (c *OIDCConnector) Policy() ResolvePolicy { return c.cfg.Policy }

func (c *OIDCConnector) clientCtx(ctx context.Context) context.Context {
	// x/oauth2 reads the client from oauth2.HTTPClient; go-oidc from its own
	// key. They share the same *http.Client.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.cfg.Client)
	return oidc.ClientContext(ctx, c.cfg.Client)
}

func (c *OIDCConnector) discover(ctx context.Context) (*oidc.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil && time.Since(c.fetchedAt) < discoveryTTL {
		return c.provider, nil
	}
	// The provider's key set keeps this context for later JWKS refreshes, so
	// it must outlive the request.
	p, err := oidc.NewProvider(c.clientCtx(context.WithoutCancel(ctx)), c.cfg.Issuer)
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
func (c *OIDCConnector) Begin(ctx context.Context, flow *Flow) (string, error) {
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

// oidcClaims are the standard claims read from the ID token and userinfo.
type oidcClaims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified flexBool `json:"email_verified"`
	Name          string   `json:"name"`
	Picture       string   `json:"picture"`
	Groups        []string `json:"groups"`
	SID           string   `json:"sid"`
}

// flexBool accepts JSON true/false and the strings "true"/"false", which some
// IdPs emit for email_verified.
type flexBool bool

func (b *flexBool) UnmarshalJSON(d []byte) error {
	var v any
	if err := json.Unmarshal(d, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case bool:
		*b = flexBool(t)
	case string:
		*b = flexBool(t == "true")
	default:
		*b = false
	}
	return nil
}

// Complete exchanges the code (with the PKCE verifier), verifies the ID token
// and its nonce, and returns the assertion. The handler has already checked
// state against the flow cookie.
func (c *OIDCConnector) Complete(ctx context.Context, r *http.Request, flow *Flow) (*Assertion, error) {
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
	idt, err := p.Verifier(&oidc.Config{ClientID: c.cfg.ClientID}).Verify(cctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("oidc %s: verify id_token: %w", c.cfg.ID, err)
	}
	if idt.Nonce == "" || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(flow.Nonce)) != 1 {
		return nil, fmt.Errorf("oidc %s: nonce mismatch", c.cfg.ID)
	}
	var cl oidcClaims
	if err := idt.Claims(&cl); err != nil {
		return nil, fmt.Errorf("oidc %s: id_token claims: %w", c.cfg.ID, err)
	}
	raw := map[string]any{}
	if err := idt.Claims(&raw); err != nil {
		return nil, fmt.Errorf("oidc %s: id_token claims: %w", c.cfg.ID, err)
	}

	// Userinfo only fills claims the ID token lacks, and must be about the
	// same subject.
	if cl.Email == "" && p.UserInfoEndpoint() != "" {
		ui, err := p.UserInfo(cctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return nil, fmt.Errorf("oidc %s: userinfo: %w", c.cfg.ID, err)
		}
		if ui.Subject != idt.Subject {
			return nil, fmt.Errorf("oidc %s: userinfo subject mismatch", c.cfg.ID)
		}
		var uc oidcClaims
		if err := ui.Claims(&uc); err != nil {
			return nil, fmt.Errorf("oidc %s: userinfo claims: %w", c.cfg.ID, err)
		}
		cl.Email, cl.EmailVerified = uc.Email, uc.EmailVerified
		if cl.Name == "" {
			cl.Name = uc.Name
		}
		if cl.Picture == "" {
			cl.Picture = uc.Picture
		}
	}

	return &Assertion{
		ProviderID:    c.cfg.ID,
		Subject:       idt.Subject,
		Email:         cl.Email,
		EmailVerified: bool(cl.EmailVerified),
		Name:          cl.Name,
		Picture:       cl.Picture,
		Groups:        cl.Groups,
		SID:           cl.SID,
		IDTokenRaw:    rawID,
		RawClaims:     raw,
	}, nil
}
