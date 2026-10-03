package action

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// SCIM provisioning tokens (WU-611, SPEC §7.8). An organisation's IdP calls
// /scim/v2 with one of these as its bearer token; the token resolves the org.

// Action names.
const (
	ActionSCIMTokenList   = "scim.token.list"
	ActionSCIMTokenCreate = "scim.token.create"
	ActionSCIMTokenRevoke = "scim.token.revoke"
)

// SCIMTokenScheme starts every SCIM token: bcscim_<prefix>_<secret>, with a
// 12-hex-digit prefix (stored plain, for lookup) and a 64-hex-digit secret.
const SCIMTokenScheme = "bcscim_"

const (
	scimPrefixBytes  = 6
	scimSecretBytes  = 32
	maxSCIMTokenName = 100
	maxSCIMTokenDays = 3650
	maxSCIMTokens    = 20
)

// Refusals (fixed copy; all wrap ErrInvalidInput).
var (
	ErrSCIMTokenName     = fmt.Errorf("%w: give the token a name of up to 100 characters", ErrInvalidInput)
	ErrSCIMTokenExpiry   = fmt.Errorf("%w: the expiry must be between 1 and 3650 days, or none", ErrInvalidInput)
	ErrSCIMTokenLimit    = fmt.Errorf("%w: this organisation has reached its limit of 20 active SCIM tokens; revoke one first", ErrInvalidInput)
	ErrSCIMTokenNotFound = fmt.Errorf("%w: that SCIM token isn't on this organisation or is already revoked", ErrInvalidInput)
)

// SCIMTokenHash is the stored hash of a whole token.
func SCIMTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ParseSCIMToken returns the lookup prefix of a well-formed token.
func ParseSCIMToken(token string) (prefix string, ok bool) {
	rest, found := strings.CutPrefix(token, SCIMTokenScheme)
	if !found {
		return "", false
	}
	prefix, secret, found := strings.Cut(rest, "_")
	if !found || len(prefix) != 2*scimPrefixBytes || len(secret) != 2*scimSecretBytes {
		return "", false
	}
	if !isLowerHex(prefix) || !isLowerHex(secret) {
		return "", false
	}
	return prefix, true
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// newSCIMToken mints a token and returns it with its prefix.
func newSCIMToken() (token, prefix string, err error) {
	var p [scimPrefixBytes]byte
	var sec [scimSecretBytes]byte
	if _, err := rand.Read(p[:]); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(sec[:]); err != nil {
		return "", "", err
	}
	prefix = hex.EncodeToString(p[:])
	return SCIMTokenScheme + prefix + "_" + hex.EncodeToString(sec[:]), prefix, nil
}

// SCIMTokenView is a token as scim.token.list returns it: never the secret
// or its hash.
type SCIMTokenView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	CreatedBy  string `json:"created_by"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	CreatedAt  string `json:"created_at"`
	// Status is active, expired or revoked.
	Status string `json:"status"`
}

// SCIMTokenCreated is scim.token.create's result. Token is the plaintext,
// returned to the caller once; Redacted drops it for every stored copy.
type SCIMTokenCreated struct {
	SCIMTokenView
	Token string `json:"token"`
}

// Redacted implements SecretResult.
func (c SCIMTokenCreated) Redacted() any { return c.SCIMTokenView }

type scimTokenCreateInput struct {
	OrgID         string `json:"org_id,omitempty"`
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expires_in_days,omitempty"`
}

type scimTokenIDInput struct {
	OrgID string `json:"org_id,omitempty"`
	ID    string `json:"id"`
}

func init() {
	for _, def := range []Definition{
		{Name: ActionSCIMTokenList, Impact: ImpactRead, Handle: handleSCIMTokenList, PrivateResult: true,
			Input: strictSchema[struct {
				OrgID string `json:"org_id,omitempty"`
			}]()},
		{Name: ActionSCIMTokenCreate, Impact: ImpactHigh, Handle: handleSCIMTokenCreate, PrivateResult: true,
			Input: strictSchema[scimTokenCreateInput]()},
		{Name: ActionSCIMTokenRevoke, Impact: ImpactHigh, Handle: handleSCIMTokenRevoke,
			Input: strictSchema[scimTokenIDInput]()},
	} {
		def.Permission = PermissionOrgSSO
		def.Scope = ScopeOrg
		Register(def)
	}
}

func scimTokenStatus(revoked, expires sql.NullString, now time.Time) string {
	switch {
	case revoked.Valid:
		return "revoked"
	case expires.Valid && expires.String <= now.UTC().Format(timeFormat):
		return "expired"
	}
	return "active"
}

func handleSCIMTokenList(ctx context.Context, ac ActionCtx, _ json.RawMessage) (any, error) {
	rows, err := ac.Tx.ListSCIMTokens(ctx, ac.Org)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionSCIMTokenList, err)
	}
	now := time.Now()
	out := make([]SCIMTokenView, 0, len(rows))
	for _, t := range rows {
		out = append(out, SCIMTokenView{
			ID: t.ID, Name: t.Name, Prefix: t.Prefix, CreatedBy: t.CreatedBy,
			ExpiresAt: t.ExpiresAt.String, LastUsedAt: t.LastUsedAt.String, RevokedAt: t.RevokedAt.String,
			CreatedAt: t.CreatedAt, Status: scimTokenStatus(t.RevokedAt, t.ExpiresAt, now),
		})
	}
	return out, nil
}

func validTokenName(s string) bool {
	if s == "" || len(s) > maxSCIMTokenName {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func handleSCIMTokenCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input scimTokenCreateInput
	if err := strictDecode(in, &input); err != nil {
		return nil, err
	}
	if ac.Org == PlatformOrgID {
		return nil, ErrPlatformOrgSSO
	}
	// The plaintext token is in the result: an agent's tool results are
	// persisted in its run log, so only people (and their API keys) mint
	// tokens.
	if ac.Actor.Type == ActorAgent || ac.Actor.Type == ActorService {
		return nil, ErrForbidden
	}
	name := strings.TrimSpace(input.Name)
	if !validTokenName(name) {
		return nil, ErrSCIMTokenName
	}
	if input.ExpiresInDays < 0 || input.ExpiresInDays > maxSCIMTokenDays {
		return nil, ErrSCIMTokenExpiry
	}
	now := time.Now().UTC()
	q := ac.Tx.Queries
	n, err := q.CountActiveSCIMTokens(ctx, sqlc.CountActiveSCIMTokensParams{OrgID: ac.Org, Now: sql.NullString{String: now.Format(timeFormat), Valid: true}})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionSCIMTokenCreate, err)
	}
	if n >= maxSCIMTokens {
		return nil, ErrSCIMTokenLimit
	}
	token, prefix, err := newSCIMToken()
	if err != nil {
		return nil, fmt.Errorf("%s: rand: %w", ActionSCIMTokenCreate, err)
	}
	expires := sql.NullString{}
	if input.ExpiresInDays > 0 {
		expires = sql.NullString{String: now.AddDate(0, 0, input.ExpiresInDays).Format(timeFormat), Valid: true}
	}
	createdBy := ac.Actor.ID
	if ac.Actor.Type == ActorAPIKey && ac.Actor.OwnerUserID != "" {
		createdBy = ac.Actor.OwnerUserID
	}
	id := newID()
	created := now.Format(timeFormat)
	if err := q.CreateSCIMToken(ctx, sqlc.CreateSCIMTokenParams{
		ID: id, OrgID: ac.Org, Name: name, Prefix: prefix, TokenHash: SCIMTokenHash(token),
		CreatedBy: createdBy, ExpiresAt: expires, CreatedAt: created,
	}); err != nil {
		return nil, fmt.Errorf("%s: %w", ActionSCIMTokenCreate, err)
	}
	return SCIMTokenCreated{
		SCIMTokenView: SCIMTokenView{ID: id, Name: name, Prefix: prefix, CreatedBy: createdBy,
			ExpiresAt: expires.String, CreatedAt: created, Status: "active"},
		Token: token,
	}, nil
}

func handleSCIMTokenRevoke(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input scimTokenIDInput
	if err := strictDecode(in, &input); err != nil {
		return nil, err
	}
	n, err := ac.Tx.RevokeSCIMToken(ctx, sqlc.RevokeSCIMTokenParams{
		Now: sql.NullString{String: time.Now().UTC().Format(timeFormat), Valid: true},
		ID:  strings.TrimSpace(input.ID), OrgID: ac.Org,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionSCIMTokenRevoke, err)
	}
	if n == 0 {
		return nil, ErrSCIMTokenNotFound
	}
	return map[string]string{"id": input.ID}, nil
}
