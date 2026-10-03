// Package idp is the sign-in provider registry (SPEC §7.1): auth_providers
// rows, the preset catalogue, env seeding, and the connectors (generic OIDC
// and GitHub) the login handler in internal/auth drives.
package idp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/event"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// InvalidatingEvents are the bus events after which the registry reloads
// (the idp.* actions, WU-603/607).
var InvalidatingEvents = []string{
	"idp.create", "idp.update", "idp.delete", "idp.enable", "idp.disable",
	"org.idp.create", "org.idp.update", "org.idp.delete", "org.idp.enable", "org.idp.disable",
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// reservedIDs would collide with fixed /auth/* routes (SPEC §7.2).
var reservedIDs = map[string]bool{
	"logout": true, "saml": true, "oidc": true, "sso": true, "passkey": true, "setup": true,
}

// ValidateID checks a provider id: lower-case letters, digits and hyphens,
// at most 63 characters, not a reserved route segment.
func ValidateID(id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("provider id %q must be lower-case letters, digits and hyphens", id)
	}
	if reservedIDs[id] {
		return fmt.Errorf("provider id %q is reserved", id)
	}
	return nil
}

// Options configures a Registry.
type Options struct {
	DB *sql.DB
	// EncKey is the 32-byte key client_secret_enc is sealed with
	// (tenant.PadKey(BC_SECRET_KEY)).
	EncKey  []byte
	BaseURL string
	// Client is the IdP HTTP client shared by every connector; nil =
	// NewIdPClient(nil).
	Client *http.Client
	// OrgClient is the HTTP client for organisation-owned providers. nil =
	// NewOrgIdPClient(OrgAllowPrivate): private and loopback addresses are
	// refused unless OrgAllowPrivate (BC_ORG_IDP_ALLOW_PRIVATE, Q11).
	OrgClient       *http.Client
	OrgAllowPrivate bool
	// GitHubAPIBase overrides the API base derived from a github row's
	// issuer (tests point it at a fake). Empty = api.github.com for
	// github.com, else <issuer>/api/v3 (GitHub Enterprise Server).
	GitHubAPIBase string
}

// ProviderInfo describes an enabled provider for listing (the /login page,
// WU-603). It carries no secrets.
type ProviderInfo struct {
	ID          string
	OrgID       string // "" = platform provider
	Kind        string
	Preset      string
	DisplayName string
	ManagedBy   string
	Position    int64
}

type entry struct {
	info ProviderInfo
	conn auth.Connector
	err  error // configuration error: this provider cannot be used
}

// Registry serves connectors built from the enabled auth_providers rows.
// Rows are loaded and connectors built on first use and cached until
// Invalidate; each connector caches its own OIDC discovery for DiscoveryTTL.
// A row that cannot be built (bad preset, undecryptable secret) fails only
// its own logins.
type Registry struct {
	opts Options

	mu      sync.Mutex
	loaded  bool
	entries map[string]entry
	order   []ProviderInfo
}

// New builds a registry; nothing is read until first use.
func New(opts Options) *Registry {
	if opts.Client == nil {
		opts.Client = NewIdPClient(nil)
	}
	if opts.OrgClient == nil {
		opts.OrgClient = NewOrgIdPClient(opts.OrgAllowPrivate)
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	return &Registry{opts: opts}
}

var _ auth.ConnectorSource = (*Registry)(nil)

// Connector returns the connector for an enabled provider id, or
// auth.ErrUnknownProvider.
func (r *Registry) Connector(ctx context.Context, id string) (auth.Connector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadLocked(ctx); err != nil {
		return nil, err
	}
	e, ok := r.entries[id]
	if !ok {
		return nil, auth.ErrUnknownProvider
	}
	if e.err != nil {
		return nil, e.err
	}
	return e.conn, nil
}

// Providers lists the enabled providers in display order (position, id),
// including ones whose configuration is currently broken.
func (r *Registry) Providers(ctx context.Context) ([]ProviderInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.loadLocked(ctx); err != nil {
		return nil, err
	}
	return append([]ProviderInfo(nil), r.order...), nil
}

// Invalidate drops every cached connector; the next lookup reloads the rows.
func (r *Registry) Invalidate() {
	r.mu.Lock()
	r.loaded, r.entries, r.order = false, nil, nil
	r.mu.Unlock()
}

// Watch invalidates the registry on every InvalidatingEvents bus event until
// the returned stop func is called.
func (r *Registry) Watch(bus *event.Bus) (stop func()) {
	names := map[string]struct{}{}
	for _, n := range InvalidatingEvents {
		names[n] = struct{}{}
	}
	sub, unsub := bus.Subscribe(event.Filter{Names: names}, 16)
	go func() {
		for range sub.C {
			r.Invalidate()
		}
	}()
	return unsub
}

func (r *Registry) loadLocked(ctx context.Context) error {
	if r.loaded {
		return nil
	}
	rows, err := sqlc.New(r.opts.DB).ListEnabledAuthProviders(ctx)
	if err != nil {
		return fmt.Errorf("idp: load providers: %w", err)
	}
	r.entries = make(map[string]entry, len(rows))
	r.order = make([]ProviderInfo, 0, len(rows))
	for _, row := range rows {
		info := ProviderInfo{
			ID: row.ID, OrgID: row.OrgID.String, Kind: row.Kind, Preset: row.Preset,
			DisplayName: row.DisplayName, ManagedBy: row.ManagedBy, Position: row.Position,
		}
		conn, err := r.build(row)
		if err != nil {
			err = fmt.Errorf("idp: provider %s: %w", row.ID, err)
		}
		r.entries[row.ID] = entry{info: info, conn: conn, err: err}
		r.order = append(r.order, info)
	}
	r.loaded = true
	return nil
}

// build turns one row into a connector without any network traffic.
func (r *Registry) build(row sqlc.AuthProvider) (auth.Connector, error) {
	secret := ""
	if row.ClientSecretEnc != "" {
		s, err := tenant.Decrypt(r.opts.EncKey, row.ClientSecretEnc)
		if err != nil {
			return nil, errors.New("client secret cannot be decrypted (BC_SECRET_KEY changed?)")
		}
		secret = s
	}
	policy := auth.ResolvePolicy{TrustEmail: row.TrustEmail == 1, AllowSignup: row.AllowSignup == 1}
	client := r.opts.Client
	if row.OrgID.Valid {
		// Org-owned (SPEC §7.4): never open sign-up, whatever the row says,
		// and outbound traffic through the org SSRF guard.
		policy.OrgID, policy.AllowSignup = row.OrgID.String, false
		client = r.opts.OrgClient
		if row.Kind != KindOIDC {
			return nil, fmt.Errorf("organisation providers must be OpenID Connect, not %s", row.Kind)
		}
	}
	switch row.Kind {
	case KindGitHub:
		web := strings.TrimRight(row.Issuer, "/")
		if web == "" {
			web = GitHubWebBase
		}
		api := r.opts.GitHubAPIBase
		if api == "" {
			api = GitHubAPIBase
			if web != GitHubWebBase {
				api = web + "/api/v3"
			}
		}
		return NewGitHubConnector(GitHubConfig{
			ID: row.ID, ClientID: row.ClientID, ClientSecret: secret, BaseURL: r.opts.BaseURL,
			WebBase: web, APIBase: api, Client: client, Policy: &policy,
		}), nil
	case KindOIDC:
		cfg, err := r.oidcConfig(row, secret, policy)
		if err != nil {
			return nil, err
		}
		cfg.Client = client
		return NewOIDCConnector(cfg), nil
	case KindSAML:
		return nil, errors.New("SAML providers are not supported yet")
	}
	return nil, fmt.Errorf("unknown kind %q", row.Kind)
}

// oidcConfig derives the generic connector's configuration from a row and
// its preset: the row wins where set, the preset fills the rest.
func (r *Registry) oidcConfig(row sqlc.AuthProvider, secret string, policy auth.ResolvePolicy) (OIDCConfig, error) {
	p, ok := LookupPreset(row.Preset)
	if !ok || p.Kind != KindOIDC {
		return OIDCConfig{}, fmt.Errorf("unknown OIDC preset %q", row.Preset)
	}
	if err := ValidateIssuer(row.Issuer); err != nil {
		return OIDCConfig{}, err
	}
	claims, err := p.Claims.Overlay(row.ClaimMapJson)
	if err != nil {
		return OIDCConfig{}, err
	}
	scopes := strings.Fields(row.Scopes)
	if len(scopes) == 0 {
		scopes = p.Scopes
	}
	cfg := OIDCConfig{
		ID: row.ID, Issuer: row.Issuer, ClientID: row.ClientID, ClientSecret: secret,
		RedirectURL: CallbackURL(r.opts.BaseURL, row.ID), Scopes: scopes, Claims: claims,
		Policy: policy, Client: r.opts.Client,
	}
	if row.Preset == "microsoft" {
		if _, multi := entraTenant(row.Issuer); multi {
			cfg.EntraMultiTenant = true
			if s := strings.TrimSpace(row.AllowedTenantsJson); s != "" {
				if err := json.Unmarshal([]byte(s), &cfg.AllowedTenants); err != nil {
					return OIDCConfig{}, fmt.Errorf("allowed tenants: %w", err)
				}
			}
		}
	}
	return cfg, nil
}
