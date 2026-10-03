package idp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// PermissionPlatformIdP gates every platform-provider action (SPEC §7.4).
// The platform Owner role's "*" grant covers it.
const PermissionPlatformIdP = "platform.idp"

// Action names. idp.create|update|delete|enable|disable are the
// InvalidatingEvents the registry watches.
const (
	ActionList     = "idp.list"
	ActionGet      = "idp.get"
	ActionCreate   = "idp.create"
	ActionUpdate   = "idp.update"
	ActionDelete   = "idp.delete"
	ActionEnable   = "idp.enable"
	ActionDisable  = "idp.disable"
	ActionDiscover = "idp.discover"
)

// Field limits for admin input.
const (
	maxDisplayName = 100
	maxClientID    = 512
	maxSecret      = 4096
	maxScopes      = 20
	maxScopeLen    = 200
	maxClaimPath   = 200
	maxTenants     = 50
)

// ErrEnvManaged refuses changes to a provider seeded from BC_* variables.
var ErrEnvManaged = errors.New("is configured by environment variables; change it there and restart")

var (
	scopeRe  = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`) // RFC 6749 scope-token
	tenantRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func init() {
	platform := func(name string, impact action.Impact, schema action.Schema, h action.HandlerFunc, private bool) {
		action.Register(action.Definition{
			Name:          name,
			Impact:        impact,
			Permission:    PermissionPlatformIdP,
			Scope:         action.ScopePlatform,
			Input:         schema,
			Handle:        platformOnly(h),
			PrivateResult: private,
		})
	}
	platform(ActionList, action.ImpactRead, decodeSchema[struct{}](), handleList, true)
	platform(ActionGet, action.ImpactRead, decodeSchema[idInput](), handleGet, true)
	platform(ActionCreate, action.ImpactHigh, decodeSchema[ProviderInput](), handleCreate, false)
	platform(ActionUpdate, action.ImpactHigh, decodeSchema[ProviderInput](), handleUpdate, false)
	platform(ActionDelete, action.ImpactHigh, decodeSchema[idInput](), handleDelete, false)
	platform(ActionEnable, action.ImpactHigh, decodeSchema[idInput](), handleSetEnabled(true), false)
	platform(ActionDisable, action.ImpactHigh, decodeSchema[idInput](), handleSetEnabled(false), false)
	platform(ActionDiscover, action.ImpactRead, decodeSchema[DiscoverInput](), handleDiscover, true)
}

// platformOnly refuses calls that carry a tenant scope. Platform-scope
// permission is meant to come from the platform org; a caller-supplied org id
// would otherwise be checked against that org's grants, where an org Owner
// holds "*". Dispatch now refuses a tenant id on every platform-scope action
// (WU-603a); this stays as defence in depth until WU-607 adds org-owned rows.
func platformOnly(h action.HandlerFunc) action.HandlerFunc {
	return func(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
		if ac.Org != "" || ac.Team != "" || ac.Proj != "" {
			return nil, fmt.Errorf("%w: platform sign-in providers are not managed from an organisation", action.ErrForbidden)
		}
		return h(ctx, ac, in)
	}
}

// decodeSchema validates that the input decodes strictly into T.
func decodeSchema[T any]() action.Schema {
	return action.FuncSchema(func(raw json.RawMessage) error {
		var v T
		return decodeStrict(raw, &v)
	})
}

func decodeStrict(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", action.ErrInvalidInput, err)
	}
	return nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{action.ErrInvalidInput}, args...)...)
}

type idInput struct {
	ID string `json:"id"`
}

// ProviderInput is the idp.create / idp.update input. ClientSecret is
// write-only: it is sealed into client_secret_enc and never returned; on
// update an empty value keeps the stored secret.
type ProviderInput struct {
	ID             string            `json:"id"`
	Preset         string            `json:"preset"`
	Kind           string            `json:"kind,omitempty"`
	DisplayName    string            `json:"display_name,omitempty"`
	Params         map[string]string `json:"params,omitempty"`
	ClientID       string            `json:"client_id"`
	ClientSecret   string            `json:"client_secret,omitempty"`
	Scopes         string            `json:"scopes,omitempty"`
	ClaimMap       map[string]string `json:"claim_map,omitempty"`
	TrustEmail     *bool             `json:"trust_email,omitempty"`
	AllowSignup    *bool             `json:"allow_signup,omitempty"`
	AllowedTenants []string          `json:"allowed_tenants,omitempty"`
	Position       *int64            `json:"position,omitempty"`
	// IdPLogout: on sign-out, also end the session at the identity provider
	// when it publishes an end_session_endpoint (SPEC §7.6). Default: the
	// preset's SupportsLogout. Always off for GitHub.
	IdPLogout *bool `json:"idp_logout,omitempty"`
	// MetadataURL / MetadataXML describe a SAML IdP (exactly one; WU-610).
	// For SAML, ClaimMap keys are subject, email, name and groups (attribute
	// names) and ClientID/ClientSecret/Scopes must be empty. The SP key pair
	// is generated on create and never returned.
	MetadataURL string `json:"metadata_url,omitempty"`
	MetadataXML string `json:"metadata_xml,omitempty"`
	// Enabled applies to idp.create only (default true); use
	// idp.enable/idp.disable afterwards.
	Enabled *bool `json:"enabled,omitempty"`
}

// ProviderView is a provider as the idp.list / idp.get actions return it.
// It never carries the client secret, only whether one is stored.
type ProviderView struct {
	ID             string            `json:"id"`
	Kind           string            `json:"kind"`
	Preset         string            `json:"preset"`
	DisplayName    string            `json:"display_name"`
	Enabled        bool              `json:"enabled"`
	ManagedBy      string            `json:"managed_by"`
	Issuer         string            `json:"issuer"`
	Params         map[string]string `json:"params,omitempty"`
	ClientID       string            `json:"client_id"`
	SecretSet      bool              `json:"secret_set"`
	Scopes         string            `json:"scopes"`
	ClaimMap       map[string]string `json:"claim_map"`
	TrustEmail     bool              `json:"trust_email"`
	AllowSignup    bool              `json:"allow_signup"`
	AllowedTenants []string          `json:"allowed_tenants"`
	Position       int64             `json:"position"`
	IdPLogout      bool              `json:"idp_logout"`
	// SAML only: IdP metadata source and the (public) SP certificate.
	MetadataURL   string `json:"metadata_url,omitempty"`
	MetadataXML   string `json:"metadata_xml,omitempty"`
	SPCert        string `json:"sp_cert,omitempty"`
	IdentityCount int64  `json:"identity_count"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

func viewOf(r sqlc.ListPlatformAuthProvidersRow) ProviderView {
	v := ProviderView{
		ID: r.ID, Kind: r.Kind, Preset: r.Preset, DisplayName: r.DisplayName,
		Enabled: r.Enabled == 1, ManagedBy: r.ManagedBy, Issuer: r.Issuer,
		ClientID: r.ClientID, SecretSet: r.HasSecret == 1, Scopes: r.Scopes,
		ClaimMap: map[string]string{}, TrustEmail: r.TrustEmail == 1,
		AllowSignup: r.AllowSignup == 1, AllowedTenants: []string{},
		Position: r.Position, IdPLogout: r.IdpLogout == 1, IdentityCount: r.IdentityCount,
		MetadataURL: r.SamlMetadataUrl, MetadataXML: r.SamlMetadataXml, SPCert: r.SpCert,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	_ = json.Unmarshal([]byte(r.ClaimMapJson), &v.ClaimMap)
	_ = json.Unmarshal([]byte(r.AllowedTenantsJson), &v.AllowedTenants)
	if p, ok := LookupPreset(r.Preset); ok {
		if params, ok := p.ParseIssuer(r.Issuer); ok && len(p.Params) > 0 {
			v.Params = params
		}
	}
	return v
}

func handleList(ctx context.Context, ac action.ActionCtx, _ json.RawMessage) (any, error) {
	rows, err := ac.Tx.ListPlatformAuthProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("idp.list: %w", err)
	}
	out := make([]ProviderView, 0, len(rows))
	for _, r := range rows {
		out = append(out, viewOf(r))
	}
	return out, nil
}

func handleGet(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
	var input idInput
	if err := decodeStrict(in, &input); err != nil {
		return nil, err
	}
	rows, err := ac.Tx.ListPlatformAuthProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("idp.get: %w", err)
	}
	for _, r := range rows {
		if r.ID == input.ID {
			return viewOf(r), nil
		}
	}
	return nil, invalid("no sign-in provider %q", input.ID)
}

// platformRow loads a platform provider row for a mutation, refusing unknown,
// org-owned and env-managed providers.
func platformRow(ctx context.Context, q *action.Queries, id string) (sqlc.AuthProvider, error) {
	row, err := q.GetAuthProvider(ctx, id)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && row.OrgID.Valid) {
		return row, invalid("no sign-in provider %q", id)
	}
	if err != nil {
		return row, fmt.Errorf("idp: load %s: %w", id, err)
	}
	if row.ManagedBy == "env" {
		return row, fmt.Errorf("%w: provider %q %w", action.ErrInvalidInput, id, ErrEnvManaged)
	}
	return row, nil
}

// normalised is a validated ProviderInput ready to store.
type normalised struct {
	kind, preset, displayName, issuer, clientID, scopes string
	claimMapJSON, tenantsJSON                           string
	metadataURL, metadataXML                            string
	trust, signup, idpLogout                            int64
}

// maxMetadataXML bounds pasted SAML IdP metadata.
const maxMetadataXML = 512 << 10

// normalise validates in against its preset. existing is the stored row on
// update (nil on create) and supplies defaults for omitted fields.
func normalise(in ProviderInput, existing *sqlc.AuthProvider) (normalised, error) {
	var n normalised
	p, ok := LookupPreset(in.Preset)
	if !ok || in.Preset == "" {
		return n, invalid("unknown preset %q", in.Preset)
	}
	switch p.Kind {
	case KindOIDC, KindGitHub, KindSAML:
	default:
		return n, invalid("preset %q is not supported yet", p.ID)
	}
	if in.Kind != "" && in.Kind != p.Kind {
		return n, invalid("kind %q does not match preset %q (%s)", in.Kind, p.ID, p.Kind)
	}
	if existing != nil && existing.Kind != p.Kind {
		return n, invalid("a %s provider cannot be changed to a %s preset; create a new provider", existing.Kind, p.Kind)
	}
	n.kind, n.preset = p.Kind, p.ID

	n.displayName = strings.TrimSpace(in.DisplayName)
	if n.displayName == "" {
		n.displayName = p.DisplayName
	}
	if err := plainText("display name", n.displayName, maxDisplayName); err != nil {
		return n, err
	}

	for k, v := range in.Params {
		if !presetHasParam(p, k) {
			return n, invalid("preset %s has no parameter %q", p.ID, k)
		}
		if err := plainText(k, v, 2048); err != nil {
			return n, err
		}
	}
	if p.Kind == KindSAML {
		if err := normaliseSAML(in, &n); err != nil {
			return n, err
		}
		return n, normalisePolicy(in, p, existing, &n)
	}
	issuer, err := p.ExpandIssuer(in.Params)
	if err != nil {
		return n, invalid("%v", err)
	}
	n.issuer = issuer

	n.clientID = strings.TrimSpace(in.ClientID)
	if n.clientID == "" {
		return n, invalid("client ID is required")
	}
	if err := plainText("client ID", n.clientID, maxClientID); err != nil {
		return n, err
	}

	scopes := strings.Fields(in.Scopes)
	if len(scopes) > maxScopes {
		return n, invalid("at most %d scopes", maxScopes)
	}
	for _, s := range scopes {
		if len(s) > maxScopeLen || !scopeRe.MatchString(s) {
			return n, invalid("invalid scope %q", s)
		}
	}
	if len(scopes) > 0 && p.Kind == KindOIDC && !containsString(scopes, "openid") {
		return n, invalid("OpenID Connect scopes must include openid")
	}
	n.scopes = strings.Join(scopes, " ")

	claims := map[string]string{}
	for k, v := range in.ClaimMap {
		v = strings.TrimSpace(v)
		if err := plainText("claim "+k, v, maxClaimPath); err != nil {
			return n, err
		}
		claims[k] = v
	}
	if p.Kind == KindGitHub && len(claims) > 0 {
		return n, invalid("GitHub has no claim map")
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return n, fmt.Errorf("idp: claim map: %w", err)
	}
	if _, err := p.Claims.Overlay(string(b)); err != nil {
		return n, invalid("%v", err)
	}
	n.claimMapJSON = string(b)

	_, multi := entraTenant(issuer)
	multi = multi && p.ID == "microsoft"
	if len(in.AllowedTenants) > 0 && !multi {
		return n, invalid("allowed tenants apply only to a multi-tenant Microsoft provider (tenant organizations or common)")
	}
	if len(in.AllowedTenants) > maxTenants {
		return n, invalid("at most %d allowed tenants", maxTenants)
	}
	tenants := []string{}
	for _, t := range in.AllowedTenants {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if !tenantRe.MatchString(t) {
			return n, invalid("allowed tenant %q is not a tenant ID (GUID)", t)
		}
		tenants = append(tenants, t)
	}
	b, err = json.Marshal(tenants)
	if err != nil {
		return n, fmt.Errorf("idp: tenants: %w", err)
	}
	n.tenantsJSON = string(b)
	return n, normalisePolicy(in, p, existing, &n)
}

// normalisePolicy fills the sign-in policy fields shared by every kind.
func normalisePolicy(in ProviderInput, p Preset, existing *sqlc.AuthProvider, n *normalised) error {
	trust, signup := p.TrustEmail, false
	if existing != nil {
		trust, signup = existing.TrustEmail == 1, existing.AllowSignup == 1
	}
	if in.TrustEmail != nil {
		trust = *in.TrustEmail
	}
	if in.AllowSignup != nil {
		signup = *in.AllowSignup
	}
	n.trust, n.signup = b2i(trust), b2i(signup)

	logout := p.SupportsLogout
	if existing != nil {
		logout = existing.IdpLogout == 1
	}
	if in.IdPLogout != nil {
		logout = *in.IdPLogout
	}
	n.idpLogout = b2i(logout && (p.Kind == KindOIDC || p.Kind == KindSAML))
	return nil
}

// normaliseSAML validates the SAML-specific fields: IdP metadata (one of
// URL or XML, XML parsed now), attribute overrides, and no OIDC fields.
func normaliseSAML(in ProviderInput, n *normalised) error {
	if strings.TrimSpace(in.ClientID) != "" || in.ClientSecret != "" || strings.TrimSpace(in.Scopes) != "" ||
		len(in.Params) > 0 || len(in.AllowedTenants) > 0 {
		return invalid("SAML providers take IdP metadata, not a client ID, secret, scopes, issuer or tenants")
	}
	n.tenantsJSON = "[]"
	mu, mx := strings.TrimSpace(in.MetadataURL), strings.TrimSpace(in.MetadataXML)
	switch {
	case mu != "" && mx != "":
		return invalid("give either a metadata URL or metadata XML, not both")
	case mu != "":
		if err := plainText("metadata URL", mu, 2048); err != nil {
			return err
		}
		if err := ValidateMetadataURL(mu); err != nil {
			return invalid("%v", err)
		}
	case mx != "":
		if len(mx) > maxMetadataXML {
			return invalid("metadata XML is too large")
		}
		if _, err := ParseIdPMetadata([]byte(mx)); err != nil {
			return invalid("%v", err)
		}
	default:
		return invalid("a SAML provider needs the identity provider's metadata URL or XML")
	}
	n.metadataURL, n.metadataXML = mu, mx
	claims := map[string]string{}
	for k, v := range in.ClaimMap {
		v = strings.TrimSpace(v)
		if err := plainText("attribute "+k, v, maxClaimPath); err != nil {
			return err
		}
		if v != "" {
			claims[k] = v
		}
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("idp: attribute map: %w", err)
	}
	if _, err := ParseSAMLAttrs(string(b)); err != nil {
		return invalid("%v", err)
	}
	n.claimMapJSON = string(b)
	return nil
}

func presetHasParam(p Preset, name string) bool {
	for _, pp := range p.Params {
		if pp.Name == name {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// plainText rejects over-long values and control characters.
func plainText(field, v string, limit int) error {
	if len(v) > limit {
		return invalid("%s is too long (max %d)", field, limit)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return invalid("%s contains control characters", field)
		}
	}
	return nil
}

// spKeyPair generates and seals a SAML provider's SP key pair ("" for other
// kinds).
func spKeyPair(secretKey []byte, kind, id string) (keyEnc, cert string, err error) {
	if kind != KindSAML {
		return "", "", nil
	}
	keyPEM, cert, err := GenerateSPKeyPair(id)
	if err != nil {
		return "", "", err
	}
	if keyEnc, err = sealSPKey(secretKey, keyPEM); err != nil {
		return "", "", err
	}
	return keyEnc, cert, nil
}

// sealSecret validates and encrypts a client secret.
func sealSecret(key []byte, secret string) (string, error) {
	if len(secret) > maxSecret {
		return "", invalid("client secret is too long")
	}
	if strings.TrimSpace(secret) != secret {
		return "", invalid("client secret has leading or trailing spaces")
	}
	if len(key) != 32 {
		return "", errors.New("idp: no BC_SECRET_KEY to seal the client secret with")
	}
	enc, err := tenant.Encrypt(key, secret)
	if err != nil {
		return "", fmt.Errorf("idp: seal client secret: %w", err)
	}
	return enc, nil
}

// mutationResult is what every idp mutation returns (and so what its event
// and audit row carry): identifiers and state only, never configuration
// secrets.
type mutationResult struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

func handleCreate(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
	var input ProviderInput
	if err := decodeStrict(in, &input); err != nil {
		return nil, err
	}
	if err := ValidateID(input.ID); err != nil {
		return nil, invalid("%v", err)
	}
	if _, err := ac.Tx.GetAuthProvider(ctx, input.ID); err == nil {
		return nil, invalid("a sign-in provider with id %q already exists", input.ID)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("idp.create: %w", err)
	}
	n, err := normalise(input, nil)
	if err != nil {
		return nil, err
	}
	secretEnc := ""
	if input.ClientSecret != "" {
		if secretEnc, err = sealSecret(ac.SecretKey, input.ClientSecret); err != nil {
			return nil, err
		}
	} else if n.kind == KindGitHub {
		return nil, invalid("GitHub needs a client secret")
	}
	keyEnc, cert, err := spKeyPair(ac.SecretKey, n.kind, input.ID)
	if err != nil {
		return nil, err
	}
	pos := int64(0)
	if input.Position != nil {
		pos = *input.Position
	} else if pos, err = ac.Tx.NextAuthProviderPosition(ctx); err != nil {
		return nil, fmt.Errorf("idp.create: position: %w", err)
	}
	enabled := input.Enabled == nil || *input.Enabled
	if err := ac.Tx.CreateAuthProvider(ctx, sqlc.CreateAuthProviderParams{
		ID: input.ID, Kind: n.kind, Preset: n.preset, DisplayName: n.displayName,
		Enabled: b2i(enabled), Issuer: n.issuer, ClientID: n.clientID, ClientSecretEnc: secretEnc,
		Scopes: n.scopes, ClaimMapJson: n.claimMapJSON, TrustEmail: n.trust, AllowSignup: n.signup,
		AllowedTenantsJson: n.tenantsJSON, Position: pos, IdpLogout: n.idpLogout,
		SamlMetadataUrl: n.metadataURL, SamlMetadataXml: n.metadataXML, SpKeyEnc: keyEnc, SpCert: cert,
	}); err != nil {
		return nil, fmt.Errorf("idp.create: %w", err)
	}
	return mutationResult{ID: input.ID, Enabled: enabled}, nil
}

func handleUpdate(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
	var input ProviderInput
	if err := decodeStrict(in, &input); err != nil {
		return nil, err
	}
	if input.Enabled != nil {
		return nil, invalid("use idp.enable or idp.disable to change whether a provider is enabled")
	}
	row, err := platformRow(ctx, ac.Tx, input.ID)
	if err != nil {
		return nil, err
	}
	n, err := normalise(input, &row)
	if err != nil {
		return nil, err
	}
	secretEnc := row.ClientSecretEnc
	if input.ClientSecret != "" {
		if secretEnc, err = sealSecret(ac.SecretKey, input.ClientSecret); err != nil {
			return nil, err
		}
	}
	pos := row.Position
	if input.Position != nil {
		pos = *input.Position
	}
	if _, err := ac.Tx.UpdateAuthProvider(ctx, sqlc.UpdateAuthProviderParams{
		Preset: n.preset, DisplayName: n.displayName, Issuer: n.issuer, ClientID: n.clientID,
		ClientSecretEnc: secretEnc, Scopes: n.scopes, ClaimMapJson: n.claimMapJSON,
		TrustEmail: n.trust, AllowSignup: n.signup, AllowedTenantsJson: n.tenantsJSON,
		Position: pos, IdpLogout: n.idpLogout, SamlMetadataUrl: n.metadataURL, SamlMetadataXml: n.metadataXML,
		ID: row.ID,
	}); err != nil {
		return nil, fmt.Errorf("idp.update: %w", err)
	}
	return mutationResult{ID: row.ID, Enabled: row.Enabled == 1}, nil
}

// handleDelete removes a provider nobody signs in with. A provider that
// identities still reference is refused: deleting it would strand those
// people's sign-in method, so admins disable it instead (disabling hides it
// from /login and stops new logins while keeping the identities resolvable
// if it is re-enabled).
func handleDelete(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
	var input idInput
	if err := decodeStrict(in, &input); err != nil {
		return nil, err
	}
	row, err := platformRow(ctx, ac.Tx, input.ID)
	if err != nil {
		return nil, err
	}
	n, err := ac.Tx.CountIdentitiesByProvider(ctx, row.ID)
	if err != nil {
		return nil, fmt.Errorf("idp.delete: count identities: %w", err)
	}
	if n > 0 {
		return nil, invalid("%d people sign in with %q; disable the provider instead of deleting it", n, row.ID)
	}
	if _, err := ac.Tx.DeleteAuthProvider(ctx, row.ID); err != nil {
		return nil, fmt.Errorf("idp.delete: %w", err)
	}
	return mutationResult{ID: row.ID}, nil
}

func handleSetEnabled(on bool) action.HandlerFunc {
	return func(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
		var input idInput
		if err := decodeStrict(in, &input); err != nil {
			return nil, err
		}
		row, err := platformRow(ctx, ac.Tx, input.ID)
		if err != nil {
			return nil, err
		}
		if _, err := ac.Tx.SetAuthProviderEnabled(ctx, sqlc.SetAuthProviderEnabledParams{Enabled: b2i(on), ID: row.ID}); err != nil {
			return nil, fmt.Errorf("idp: set enabled: %w", err)
		}
		return mutationResult{ID: row.ID, Enabled: on}, nil
	}
}
