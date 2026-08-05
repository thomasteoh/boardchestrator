package action

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// --- Action definitions for API keys (WU-109) ---

type apikeyCreateInput struct {
	OrgID string   `json:"org_id"`
	Name  string   `json:"name"`
	Scope []string `json:"scope"`
}

type apikeyRevokeInput struct {
	ID     string `json:"id"`
	OrgID  string `json:"org_id"`
	UserID string `json:"user_id"`
}

type apikeyListInput struct {
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
		Name:       "apikey.list",
		Impact:     ImpactRead,
		Permission: "apikey.list",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleApikeyList,
	})
}

func handleApikeyCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input apikeyCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("apikey.create: %w", err)
	}

	// Generate prefix (8 hex chars) for lookup.
	var prefixBytes [4]byte
	if _, err := rand.Read(prefixBytes[:]); err != nil {
		return nil, fmt.Errorf("apikey.create: prefix rand: %w", err)
	}
	prefix := hex.EncodeToString(prefixBytes[:])

	// Generate secret + hash.
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, fmt.Errorf("apikey.create: secret rand: %w", err)
	}
	hash := sha256.Sum256(secret[:])

	id := newID()
	fullSecret := prefix + hex.EncodeToString(secret[:])

	scopeJSON, err := json.Marshal(input.Scope)
	if err != nil {
		return nil, fmt.Errorf("apikey.create: marshal scope: %w", err)
	}

	_, err = ac.Tx.CreateAPIKey(ctx, sqlc.CreateAPIKeyParams{
		ID:        id,
		UserID:    ac.Actor.ID,
		OrgID:     input.OrgID,
		Name:      input.Name,
		Prefix:    prefix,
		Hash:      hex.EncodeToString(hash[:]),
		ScopeJson: string(scopeJSON),
	})
	if err != nil {
		return nil, fmt.Errorf("apikey.create: %w", err)
	}

	return map[string]any{
		"id":     id,
		"secret": fullSecret,
	}, nil
}

func handleApikeyRevoke(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input apikeyRevokeInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("apikey.revoke: %w", err)
	}

	if err := ac.Tx.RevokeAPIKey(ctx, sqlc.RevokeAPIKeyParams{
		ID:     input.ID,
		UserID: ac.Actor.ID,
	}); err != nil {
		return nil, fmt.Errorf("apikey.revoke: %w", err)
	}
	return nil, nil
}

func handleApikeyList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input apikeyListInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("apikey.list: %w", err)
	}

	keys, err := ac.Tx.ListAPIKeysByUser(ctx, ac.Actor.ID)
	if err != nil {
		return nil, fmt.Errorf("apikey.list: %w", err)
	}
	return keys, nil
}
