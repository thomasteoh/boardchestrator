package action

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// --- Action definitions for API keys (WU-109; lifecycle WU-613, SPEC §7.10) ---

// Org-wide key management (WU-613): org owners (org.permissions) list and
// revoke any key bound to their org.
const (
	ActionAPIKeyOrgList   = "apikey.org_list"
	ActionAPIKeyOrgRevoke = "apikey.org_revoke"
)

// PermissionOrgPermissions is the org owner permission that manages roles,
// memberships and the org's API keys.
const PermissionOrgPermissions = "org.permissions"

const (
	// DefaultAPIKeyDays is the expiry a new key gets when the caller does
	// not choose one.
	DefaultAPIKeyDays = 90
	maxAPIKeyDays     = 3650
	maxAPIKeyName     = 100
)

// Refusals (fixed copy; all wrap ErrInvalidInput).
var (
	ErrAPIKeyName     = fmt.Errorf("%w: give the key a name of up to 100 characters", ErrInvalidInput)
	ErrAPIKeyExpiry   = fmt.Errorf("%w: the expiry must be between 1 and 3650 days, or none", ErrInvalidInput)
	ErrAPIKeyScope    = fmt.Errorf("%w: the scope must be a list of action names", ErrInvalidInput)
	ErrAPIKeyNotFound = fmt.Errorf("%w: that API key isn't on this organisation or is already revoked", ErrInvalidInput)
)

// APIKeyHash is the stored hash of a key's secret bytes.
func APIKeyHash(secret []byte) string {
	sum := sha256.Sum256(secret)
	return hex.EncodeToString(sum[:])
}

// APIKeyHashMatches compares a computed hash with the stored one in
// constant time (SPEC §7.10).
func APIKeyHashMatches(computed, stored string) bool {
	return subtle.ConstantTimeCompare([]byte(computed), []byte(stored)) == 1
}

// APIKeyView is a key as the list actions return it: never the secret or
// its hash.
type APIKeyView struct {
	ID         string `json:"id"`
	OrgID      string `json:"org_id"`
	UserID     string `json:"user_id"`
	OwnerName  string `json:"owner_name,omitempty"`
	OwnerEmail string `json:"owner_email,omitempty"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	Scope      string `json:"scope,omitempty"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	// Status is active or expired (revoked keys are not listed).
	Status string `json:"status"`
}

// APIKeyCreated is apikey.create's result. Secret is the plaintext key,
// returned to the caller once; Redacted drops it for every stored copy
// (audit, events, webhooks, idempotency), closing WU-522 for API keys.
type APIKeyCreated struct {
	APIKeyView
	Secret string `json:"secret"`
}

// Redacted implements SecretResult.
func (c APIKeyCreated) Redacted() any { return c.APIKeyView }

type apikeyCreateInput struct {
	OrgID string          `json:"org_id"`
	Name  string          `json:"name"`
	Scope json.RawMessage `json:"scope"`
	// ExpiresInDays: absent = DefaultAPIKeyDays, 0 = never, else 1-3650.
	// Forms send it as a string.
	ExpiresInDays json.RawMessage `json:"expires_in_days"`
}

type apikeyIDInput struct {
	ID     string `json:"id"`
	OrgID  string `json:"org_id"`
	UserID string `json:"user_id"`
}

func init() {
	Register(Definition{
		Name:       "apikey.create",
		Impact:     ImpactHigh,
		Permission: "apikey.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleApikeyCreate,
	})
	Register(Definition{
		Name:       "apikey.revoke",
		Impact:     ImpactHigh,
		Permission: "apikey.revoke",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleApikeyRevoke,
	})
	Register(Definition{
		Name:          "apikey.list",
		Impact:        ImpactRead,
		Permission:    "apikey.list",
		Scope:         ScopeOrg,
		Input:         FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:        handleApikeyList,
		PrivateResult: true,
	})
	Register(Definition{
		Name:          ActionAPIKeyOrgList,
		Impact:        ImpactRead,
		Permission:    PermissionOrgPermissions,
		Scope:         ScopeOrg,
		Input:         FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:        handleApikeyOrgList,
		PrivateResult: true,
	})
	Register(Definition{
		Name:       ActionAPIKeyOrgRevoke,
		Impact:     ImpactHigh,
		Permission: PermissionOrgPermissions,
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleApikeyOrgRevoke,
	})
}

// keyOwner is the user a key belongs to: the user acting, or the owner of
// the API key acting.
func keyOwner(a Actor) string {
	if a.Type == ActorAPIKey && a.OwnerUserID != "" {
		return a.OwnerUserID
	}
	return a.ID
}

// parseExpiryDays reads expires_in_days (number or numeric string).
func parseExpiryDays(raw json.RawMessage) (int, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return DefaultAPIKeyDays, nil
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return 0, ErrAPIKeyExpiry
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return DefaultAPIKeyDays, nil
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			return 0, ErrAPIKeyExpiry
		}
		n = v
	}
	if n < 0 || n > maxAPIKeyDays {
		return 0, ErrAPIKeyExpiry
	}
	return n, nil
}

// parseKeyScope accepts a list of action names or a comma/space separated
// string (forms).
func parseKeyScope(raw json.RawMessage) ([]string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return []string{}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		out := make([]string, 0, len(list))
		for _, s := range list {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, ErrAPIKeyScope
	}
	out := splitGrants(s)
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func apiKeyStatus(expires sql.NullString, now time.Time) string {
	if expires.Valid && expires.String <= now.UTC().Format(timeFormat) {
		return "expired"
	}
	return "active"
}

func handleApikeyCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input apikeyCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	// The plaintext key is in the result: an agent's tool results are
	// persisted in its run log, so only people (and their keys) mint keys.
	if ac.Actor.Type == ActorAgent || ac.Actor.Type == ActorService {
		return nil, ErrForbidden
	}
	name := strings.TrimSpace(input.Name)
	if !validTokenName(name) || len(name) > maxAPIKeyName {
		return nil, ErrAPIKeyName
	}
	days, err := parseExpiryDays(input.ExpiresInDays)
	if err != nil {
		return nil, err
	}
	scope, err := parseKeyScope(input.Scope)
	if err != nil {
		return nil, err
	}
	org := ac.Org
	if org == "" {
		org = input.OrgID
	}

	// Prefix (8 hex chars) for lookup, then a 32-byte secret, hashed.
	var prefixBytes [4]byte
	if _, err := rand.Read(prefixBytes[:]); err != nil {
		return nil, fmt.Errorf("apikey.create: prefix rand: %w", err)
	}
	prefix := hex.EncodeToString(prefixBytes[:])
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, fmt.Errorf("apikey.create: secret rand: %w", err)
	}

	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return nil, fmt.Errorf("apikey.create: marshal scope: %w", err)
	}
	now := time.Now().UTC()
	expires := sql.NullString{}
	if days > 0 {
		expires = sql.NullString{String: now.AddDate(0, 0, days).Format(timeFormat), Valid: true}
	}
	id := newID()
	owner := keyOwner(ac.Actor)
	row, err := ac.Tx.CreateAPIKey(ctx, sqlc.CreateAPIKeyParams{
		ID:        id,
		UserID:    owner,
		OrgID:     org,
		Name:      name,
		Prefix:    prefix,
		Hash:      APIKeyHash(secret[:]),
		ScopeJson: string(scopeJSON),
		ExpiresAt: expires,
	})
	if err != nil {
		return nil, fmt.Errorf("apikey.create: %w", err)
	}
	return APIKeyCreated{
		APIKeyView: APIKeyView{
			ID: id, OrgID: org, UserID: owner, Name: name, Prefix: prefix, Scope: string(scopeJSON),
			CreatedAt: row.CreatedAt, ExpiresAt: expires.String, Status: "active",
		},
		Secret: prefix + hex.EncodeToString(secret[:]),
	}, nil
}

func handleApikeyRevoke(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input apikeyIDInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	n, err := ac.Tx.RevokeAPIKey(ctx, sqlc.RevokeAPIKeyParams{
		ID:     strings.TrimSpace(input.ID),
		UserID: keyOwner(ac.Actor),
		OrgID:  ac.Org,
	})
	if err != nil {
		return nil, fmt.Errorf("apikey.revoke: %w", err)
	}
	if n == 0 {
		return nil, ErrAPIKeyNotFound
	}
	return map[string]string{"id": input.ID}, nil
}

// handleApikeyList returns the caller's own keys bound to the org.
func handleApikeyList(ctx context.Context, ac ActionCtx, _ json.RawMessage) (any, error) {
	keys, err := ac.Tx.ListUserOrgAPIKeys(ctx, sqlc.ListUserOrgAPIKeysParams{OrgID: ac.Org, UserID: keyOwner(ac.Actor)})
	if err != nil {
		return nil, fmt.Errorf("apikey.list: %w", err)
	}
	now := time.Now()
	out := make([]APIKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, APIKeyView{
			ID: k.ID, OrgID: k.OrgID, UserID: k.UserID, Name: k.Name, Prefix: k.Prefix, Scope: k.ScopeJson,
			CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt.String, ExpiresAt: k.ExpiresAt.String,
			Status: apiKeyStatus(k.ExpiresAt, now),
		})
	}
	return out, nil
}

// handleApikeyOrgList returns every unrevoked key bound to the org.
func handleApikeyOrgList(ctx context.Context, ac ActionCtx, _ json.RawMessage) (any, error) {
	keys, err := ac.Tx.ListOrgAPIKeysWithOwner(ctx, ac.Org)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionAPIKeyOrgList, err)
	}
	now := time.Now()
	out := make([]APIKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, APIKeyView{
			ID: k.ID, OrgID: ac.Org, UserID: k.UserID, OwnerName: k.OwnerName, OwnerEmail: k.OwnerEmail,
			Name: k.Name, Prefix: k.Prefix, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt.String,
			ExpiresAt: k.ExpiresAt.String, Status: apiKeyStatus(k.ExpiresAt, now),
		})
	}
	return out, nil
}

// handleApikeyOrgRevoke revokes any key bound to the org.
func handleApikeyOrgRevoke(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input apikeyIDInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	n, err := ac.Tx.RevokeOrgAPIKey(ctx, sqlc.RevokeOrgAPIKeyParams{ID: strings.TrimSpace(input.ID), OrgID: ac.Org})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ActionAPIKeyOrgRevoke, err)
	}
	if n == 0 {
		return nil, ErrAPIKeyNotFound
	}
	return map[string]string{"id": input.ID}, nil
}
