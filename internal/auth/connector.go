package auth

import (
	"context"
	"errors"
	"net/http"
)

// Authentication methods recorded on sessions (SPEC §7.3 step 6).
const (
	AuthMethodOIDC    = "oidc"
	AuthMethodGitHub  = "github"
	AuthMethodSAML    = "saml"
	AuthMethodPasskey = "passkey"
)

// Connector is one sign-in provider (SPEC §7.1). Begin returns the IdP URL to
// send the browser to for flow; Complete runs on the callback after the
// handler has matched the flow cookie's state and provider id, and returns a
// verified Assertion. Implementations live in internal/auth/idp; the
// handler finds them through a ConnectorSource (the idp.Registry).
type Connector interface {
	// ID is the provider id: the {providerID} route segment and the
	// identities.provider value.
	ID() string
	// AuthMethod is the sessions.auth_method value for logins through it.
	AuthMethod() string
	// Policy is the provider's linking and sign-up policy (SPEC §7.3).
	Policy() ResolvePolicy
	Begin(ctx context.Context, flow *Flow) (redirectURL string, err error)
	Complete(ctx context.Context, r *http.Request, flow *Flow) (*Assertion, error)
}

// Assertion is a verified statement from a provider about who signed in.
type Assertion struct {
	ProviderID    string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Groups        []string
	SID           string
	IDTokenRaw    string
	RawClaims     map[string]any
	// AccessToken is the provider's OAuth access token, kept only where a
	// feature reuses it (GitHub, WU-406); it is stored encrypted.
	AccessToken string
}

// ResolvePolicy is the per-provider policy login resolution applies.
// TrustEmail permits linking an unseen identity to an existing user by
// verified email (step 3); AllowSignup permits creating a new user (step 4).
type ResolvePolicy struct {
	TrustEmail  bool
	AllowSignup bool
}

// ErrUnknownProvider is returned by a ConnectorSource for an id that names no
// enabled provider; the handler answers 404.
var ErrUnknownProvider = errors.New("auth: unknown sign-in provider")

// ConnectorSource resolves a provider id to its connector. An error other
// than ErrUnknownProvider means the provider exists but cannot be used right
// now (bad configuration); it fails only that provider's logins.
type ConnectorSource interface {
	Connector(ctx context.Context, id string) (Connector, error)
}

// StaticConnectors is a fixed ConnectorSource keyed by Connector.ID().
type StaticConnectors map[string]Connector

// NewStaticConnectors indexes conns by id.
func NewStaticConnectors(conns ...Connector) StaticConnectors {
	m := StaticConnectors{}
	for _, c := range conns {
		m[c.ID()] = c
	}
	return m
}

// Connector implements ConnectorSource.
func (s StaticConnectors) Connector(_ context.Context, id string) (Connector, error) {
	if c, ok := s[id]; ok {
		return c, nil
	}
	return nil, ErrUnknownProvider
}
