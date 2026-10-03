package idp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Organisation-owned providers (WU-607, SPEC §7.4). Dispatch refuses an org
// id on platform-scope actions (WU-603a), so org owners manage their own
// auth_providers rows (org_id set) through these ScopeOrg actions, with
// permission org.sso. They share validation with idp.* but every query pins
// org_id = ac.Org, so an org owner never sees or touches another org's or
// the platform's providers.
const (
	ActionOrgList     = "org.idp.list"
	ActionOrgGet      = "org.idp.get"
	ActionOrgCreate   = "org.idp.create"
	ActionOrgUpdate   = "org.idp.update"
	ActionOrgDelete   = "org.idp.delete"
	ActionOrgEnable   = "org.idp.enable"
	ActionOrgDisable  = "org.idp.disable"
	ActionOrgDiscover = "org.idp.discover"
)

// orgAllowPrivate is BC_ORG_IDP_ALLOW_PRIVATE for org.idp.discover (the
// registry takes it as an option). Set by the server at startup.
var orgAllowPrivate atomic.Bool

// SetOrgAllowPrivate sets whether org.idp.discover may reach private and
// loopback addresses (Q11).
func SetOrgAllowPrivate(on bool) { orgAllowPrivate.Store(on) }

// orgInput is ProviderInput plus the org_id the generic /api/action path
// may carry (dispatch has already verified it as ac.Org).
type orgInput struct {
	ProviderInput
	OrgID string `json:"org_id,omitempty"`
}

type orgIDInput struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id,omitempty"`
}

type orgDiscoverInput struct {
	DiscoverInput
	OrgID string `json:"org_id,omitempty"`
}

func init() {
	org := func(name string, impact action.Impact, schema action.Schema, h action.HandlerFunc, private bool) {
		action.Register(action.Definition{
			Name:          name,
			Impact:        impact,
			Permission:    action.PermissionOrgSSO,
			Scope:         action.ScopeOrg,
			Input:         schema,
			Handle:        h,
			PrivateResult: private,
		})
	}
	org(ActionOrgList, action.ImpactRead, decodeSchema[struct {
		OrgID string `json:"org_id,omitempty"`
	}](), handleOrgList, true)
	org(ActionOrgGet, action.ImpactRead, decodeSchema[orgIDInput](), handleOrgGet, true)
	org(ActionOrgCreate, action.ImpactHigh, decodeSchema[orgInput](), handleOrgCreate, false)
	org(ActionOrgUpdate, action.ImpactHigh, decodeSchema[orgInput](), handleOrgUpdate, false)
	org(ActionOrgDelete, action.ImpactHigh, decodeSchema[orgIDInput](), handleOrgDelete, false)
	org(ActionOrgEnable, action.ImpactHigh, decodeSchema[orgIDInput](), handleOrgSetEnabled(true), false)
	org(ActionOrgDisable, action.ImpactHigh, decodeSchema[orgIDInput](), handleOrgSetEnabled(false), false)
	org(ActionOrgDiscover, action.ImpactRead, decodeSchema[orgDiscoverInput](), handleOrgDiscover, true)
}

func orgNull(org string) sql.NullString { return sql.NullString{String: org, Valid: org != ""} }

var slugCleanRe = regexp.MustCompile(`[^a-z0-9]+`)

// OrgIDPrefix is the id prefix an org's providers must carry: the org slug,
// lower-cased with runs of other characters turned into hyphens, then "-".
// Provider ids are global (/auth/{id}), so the prefix stops one org from
// squatting on names like "google" or another org's ids.
func OrgIDPrefix(slug string) string {
	s := strings.Trim(slugCleanRe.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	if s == "" {
		s = "org"
	}
	if len(s) > 40 {
		s = strings.TrimRight(s[:40], "-")
	}
	return s + "-"
}

// OrgProviderPrefix returns the required id prefix for orgID's providers.
func OrgProviderPrefix(ctx context.Context, q *sqlc.Queries, orgID string) (string, error) {
	o, err := q.FindOrgByID(ctx, orgID)
	if err != nil {
		return "", fmt.Errorf("org %s: %w", orgID, err)
	}
	return OrgIDPrefix(o.Slug), nil
}

func handleOrgList(ctx context.Context, ac action.ActionCtx, _ json.RawMessage) (any, error) {
	rows, err := ac.Tx.ListOrgAuthProviders(ctx, orgNull(ac.Org))
	if err != nil {
		return nil, fmt.Errorf("org.idp.list: %w", err)
	}
	out := make([]ProviderView, 0, len(rows))
	for _, r := range rows {
		out = append(out, viewOf(sqlc.ListPlatformAuthProvidersRow(r)))
	}
	return out, nil
}

func handleOrgGet(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
	var input orgIDInput
	if err := decodeStrict(in, &input); err != nil {
		return nil, err
	}
	rows, err := ac.Tx.ListOrgAuthProviders(ctx, orgNull(ac.Org))
	if err != nil {
		return nil, fmt.Errorf("org.idp.get: %w", err)
	}
	for _, r := range rows {
		if r.ID == input.ID {
			return viewOf(sqlc.ListPlatformAuthProvidersRow(r)), nil
		}
	}
	return nil, invalid("no sign-in provider %q", input.ID)
}

// orgRow loads one of ac.Org's providers; anything else (another org's,
// a platform provider, unknown) is "no such provider".
func orgRow(ctx context.Context, ac action.ActionCtx, id string) (sqlc.AuthProvider, error) {
	row, err := ac.Tx.GetOrgAuthProvider(ctx, sqlc.GetOrgAuthProviderParams{ID: id, OrgID: orgNull(ac.Org)})
	if errors.Is(err, sql.ErrNoRows) {
		return row, invalid("no sign-in provider %q", id)
	}
	if err != nil {
		return row, fmt.Errorf("org.idp: load %s: %w", id, err)
	}
	return row, nil
}

// orgPreset refuses presets an organisation cannot use: GitHub OAuth is
// not an organisation identity provider. SAML is allowed (WU-610).
func orgPreset(id string) error {
	p, ok := LookupPreset(id)
	if !ok || id == "" {
		return invalid("unknown preset %q", id)
	}
	if p.Kind != KindOIDC && p.Kind != KindSAML {
		return invalid("organisation sign-in providers must use OpenID Connect or SAML; %s isn't supported here", p.DisplayName)
	}
	return nil
}

// errOrgSignup refuses allow_signup on an org provider.
func errOrgSignup() error {
	return invalid("organisation sign-in providers can't allow open sign-up; invite people instead")
}

func handleOrgCreate(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
	var input orgInput
	if err := decodeStrict(in, &input); err != nil {
		return nil, err
	}
	pin := input.ProviderInput
	if err := ValidateID(pin.ID); err != nil {
		return nil, invalid("%v", err)
	}
	prefix, err := OrgProviderPrefix(ctx, ac.Tx.Queries, ac.Org)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(pin.ID, prefix) || len(pin.ID) == len(prefix) {
		return nil, invalid("an organisation provider's id must start with %q, for example %ssso", prefix, prefix)
	}
	if err := orgPreset(pin.Preset); err != nil {
		return nil, err
	}
	if pin.AllowSignup != nil && *pin.AllowSignup {
		return nil, errOrgSignup()
	}
	if _, err := ac.Tx.GetAuthProvider(ctx, pin.ID); err == nil {
		return nil, invalid("a sign-in provider with id %q already exists", pin.ID)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("org.idp.create: %w", err)
	}
	n, err := normalise(pin, nil)
	if err != nil {
		return nil, err
	}
	secretEnc := ""
	if pin.ClientSecret != "" {
		if secretEnc, err = sealSecret(ac.SecretKey, pin.ClientSecret); err != nil {
			return nil, err
		}
	}
	keyEnc, cert, err := spKeyPair(ac.SecretKey, n.kind, pin.ID)
	if err != nil {
		return nil, err
	}
	pos := int64(0)
	if pin.Position != nil {
		pos = *pin.Position
	} else if pos, err = ac.Tx.NextOrgAuthProviderPosition(ctx, orgNull(ac.Org)); err != nil {
		return nil, fmt.Errorf("org.idp.create: position: %w", err)
	}
	enabled := pin.Enabled == nil || *pin.Enabled
	if err := ac.Tx.CreateOrgAuthProvider(ctx, sqlc.CreateOrgAuthProviderParams{
		ID: pin.ID, OrgID: orgNull(ac.Org), Kind: n.kind, Preset: n.preset, DisplayName: n.displayName,
		Enabled: b2i(enabled), Issuer: n.issuer, ClientID: n.clientID, ClientSecretEnc: secretEnc,
		Scopes: n.scopes, ClaimMapJson: n.claimMapJSON, TrustEmail: n.trust,
		AllowedTenantsJson: n.tenantsJSON, Position: pos, IdpLogout: n.idpLogout,
		SamlMetadataUrl: n.metadataURL, SamlMetadataXml: n.metadataXML, SpKeyEnc: keyEnc, SpCert: cert,
	}); err != nil {
		return nil, fmt.Errorf("org.idp.create: %w", err)
	}
	return mutationResult{ID: pin.ID, Enabled: enabled}, nil
}

func handleOrgUpdate(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
	var input orgInput
	if err := decodeStrict(in, &input); err != nil {
		return nil, err
	}
	pin := input.ProviderInput
	if pin.Enabled != nil {
		return nil, invalid("use org.idp.enable or org.idp.disable to change whether a provider is enabled")
	}
	if pin.AllowSignup != nil && *pin.AllowSignup {
		return nil, errOrgSignup()
	}
	row, err := orgRow(ctx, ac, pin.ID)
	if err != nil {
		return nil, err
	}
	if err := orgPreset(pin.Preset); err != nil {
		return nil, err
	}
	n, err := normalise(pin, &row)
	if err != nil {
		return nil, err
	}
	secretEnc := row.ClientSecretEnc
	if pin.ClientSecret != "" {
		if secretEnc, err = sealSecret(ac.SecretKey, pin.ClientSecret); err != nil {
			return nil, err
		}
	}
	pos := row.Position
	if pin.Position != nil {
		pos = *pin.Position
	}
	if _, err := ac.Tx.UpdateOrgAuthProvider(ctx, sqlc.UpdateOrgAuthProviderParams{
		Preset: n.preset, DisplayName: n.displayName, Issuer: n.issuer, ClientID: n.clientID,
		ClientSecretEnc: secretEnc, Scopes: n.scopes, ClaimMapJson: n.claimMapJSON,
		TrustEmail: n.trust, AllowedTenantsJson: n.tenantsJSON, Position: pos, IdpLogout: n.idpLogout,
		SamlMetadataUrl: n.metadataURL, SamlMetadataXml: n.metadataXML,
		ID: row.ID, OrgID: orgNull(ac.Org),
	}); err != nil {
		return nil, fmt.Errorf("org.idp.update: %w", err)
	}
	return mutationResult{ID: row.ID, Enabled: row.Enabled == 1}, nil
}

// ErrLastEnforcedProvider refuses removing the last enabled provider of an
// org that requires single sign-on: nobody could then act in the org.
var ErrLastEnforcedProvider = fmt.Errorf("%w: this is the organisation's last enabled identity provider and single sign-on is required; turn off the requirement first", action.ErrInvalidInput)

// guardLastEnforced refuses taking row out of service when it is the last
// enabled provider of an org enforcing SSO.
func guardLastEnforced(ctx context.Context, ac action.ActionCtx, row sqlc.AuthProvider) error {
	if row.Enabled != 1 {
		return nil
	}
	st, err := ac.Tx.GetOrgSSOSettings(ctx, ac.Org)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && st.EnforceSso == 0) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("org.idp: sso settings: %w", err)
	}
	ids, err := ac.Tx.ListEnabledOrgAuthProviderIDs(ctx, orgNull(ac.Org))
	if err != nil {
		return fmt.Errorf("org.idp: providers: %w", err)
	}
	if len(ids) <= 1 {
		return ErrLastEnforcedProvider
	}
	return nil
}

func handleOrgDelete(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
	var input orgIDInput
	if err := decodeStrict(in, &input); err != nil {
		return nil, err
	}
	row, err := orgRow(ctx, ac, input.ID)
	if err != nil {
		return nil, err
	}
	n, err := ac.Tx.CountIdentitiesByProvider(ctx, row.ID)
	if err != nil {
		return nil, fmt.Errorf("org.idp.delete: count identities: %w", err)
	}
	if n > 0 {
		return nil, invalid("%d people sign in with %q; disable the provider instead of deleting it", n, row.ID)
	}
	if err := guardLastEnforced(ctx, ac, row); err != nil {
		return nil, err
	}
	if _, err := ac.Tx.DeleteOrgAuthProvider(ctx, sqlc.DeleteOrgAuthProviderParams{ID: row.ID, OrgID: orgNull(ac.Org)}); err != nil {
		return nil, fmt.Errorf("org.idp.delete: %w", err)
	}
	return mutationResult{ID: row.ID}, nil
}

func handleOrgSetEnabled(on bool) action.HandlerFunc {
	return func(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
		var input orgIDInput
		if err := decodeStrict(in, &input); err != nil {
			return nil, err
		}
		row, err := orgRow(ctx, ac, input.ID)
		if err != nil {
			return nil, err
		}
		if !on {
			if err := guardLastEnforced(ctx, ac, row); err != nil {
				return nil, err
			}
		}
		if _, err := ac.Tx.SetOrgAuthProviderEnabled(ctx, sqlc.SetOrgAuthProviderEnabledParams{
			Enabled: b2i(on), ID: row.ID, OrgID: orgNull(ac.Org),
		}); err != nil {
			return nil, fmt.Errorf("org.idp: set enabled: %w", err)
		}
		return mutationResult{ID: row.ID, Enabled: on}, nil
	}
}

// handleOrgDiscover is idp.discover for an org owner: it tests one of the
// org's own providers or an unsaved OIDC preset, through the org SSRF guard
// (private and loopback refused unless BC_ORG_IDP_ALLOW_PRIVATE).
func handleOrgDiscover(ctx context.Context, ac action.ActionCtx, in json.RawMessage) (any, error) {
	var input orgDiscoverInput
	if err := decodeStrict(in, &input); err != nil {
		return nil, err
	}
	di := input.DiscoverInput
	var issuer, presetID string
	switch {
	case di.ID != "" && (di.Preset != "" || len(di.Params) > 0):
		return nil, invalid("give either a provider id or a preset with parameters, not both")
	case di.ID != "":
		row, err := orgRow(ctx, ac, di.ID)
		if err != nil {
			return nil, err
		}
		if row.Kind != KindOIDC {
			return nil, invalid("only OpenID Connect providers publish discovery documents")
		}
		issuer, presetID = row.Issuer, row.Preset
	default:
		if err := orgPreset(di.Preset); err != nil {
			return nil, err
		}
		p, _ := LookupPreset(di.Preset)
		if p.Kind != KindOIDC {
			return nil, invalid("only OpenID Connect providers publish discovery documents")
		}
		for k := range di.Params {
			if !presetHasParam(p, k) {
				return nil, invalid("preset %s has no parameter %q", p.ID, k)
			}
		}
		iss, err := p.ExpandIssuer(di.Params)
		if err != nil {
			return nil, invalid("%v", err)
		}
		issuer, presetID = iss, p.ID
	}
	res, err := discover(ctx, NewOrgIdPClient(orgAllowPrivate.Load()), issuer, presetID)
	if err != nil {
		ref := discoveryRef()
		slog.Warn("idp: org discovery test failed", "ref", ref, "org", ac.Org, "issuer", issuer, "err", err)
		return DiscoverResult{Issuer: issuer, Ref: ref}, nil
	}
	return res, nil
}
