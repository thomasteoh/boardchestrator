package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/storage"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// storageConfigKey is the org_secrets key holding the encrypted S3 config.
const storageConfigKey = "s3_config"

// storageConfigureInput is the input to org.storage.configure (WU-506). A
// non-empty storage_config JSON replaces the org's S3 backend; empty clears it
// (falls back to local). storage_config may arrive as a JSON object or as a
// JSON-encoded string (htmx form textarea).
type storageConfigureInput struct {
	OrgID         string          `json:"org_id,omitempty"`
	StorageConfig json.RawMessage `json:"storage_config,omitempty"`
}

// handleOrgStorageConfigure saves the org's S3 storage config, encrypted, into
// org_secrets (key "s3_config"). Empty storage_config clears the backend so the
// org falls back to local storage.
func handleOrgStorageConfigure(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input storageConfigureInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("org.storage.configure: bad input: %w", err)
	}

	// Empty config (`null`, `{}`, or omitted) clears the backend → local.
	raw := string(input.StorageConfig)
	isEmpty := raw == "" || raw == "null" || raw == "{}"

	// Normalise: if storage_config is a JSON-encoded string (htmx textarea),
	// unwrap it into the raw JSON it holds.
	if !isEmpty && len(raw) > 0 && raw[0] == '"' {
		var s string
		if err := json.Unmarshal(input.StorageConfig, &s); err != nil {
			return nil, fmt.Errorf("org.storage.configure: bad storage_config string: %w", err)
		}
		raw = s
		isEmpty = raw == "" || raw == "null" || raw == "{}"
	}

	if !isEmpty {
		cfg, err := storage.ParseS3Config([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("org.storage.configure: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("org.storage.configure: %w", err)
		}
		enc, err := tenant.Encrypt(ac.SecretKey, raw)
		if err != nil {
			return nil, fmt.Errorf("org.storage.configure: encrypt: %w", err)
		}
		// Upsert: delete existing then insert (org_secrets UNIQUE(org_id,key)).
		if err := ac.Tx.DeleteOrgSecret(ctx, sqlc.DeleteOrgSecretParams{OrgID: ac.Org, Key: storageConfigKey}); err != nil {
			return nil, fmt.Errorf("org.storage.configure: delete: %w", err)
		}
		_, err = ac.Tx.CreateOrgSecret(ctx, sqlc.CreateOrgSecretParams{
			ID:         newID(),
			OrgID:      ac.Org,
			Key:        storageConfigKey,
			Ciphertext: enc,
		})
		if err != nil {
			return nil, fmt.Errorf("org.storage.configure: create: %w", err)
		}
		return map[string]any{"org_id": ac.Org, "backend": "s3"}, nil
	}

	// Clear: delete any stored config.
	if err := ac.Tx.DeleteOrgSecret(ctx, sqlc.DeleteOrgSecretParams{OrgID: ac.Org, Key: storageConfigKey}); err != nil {
		return nil, fmt.Errorf("org.storage.configure: clear: %w", err)
	}
	return map[string]any{"org_id": ac.Org, "backend": "local"}, nil
}

// handleOrgStorageStatus reports the org's storage backend without exposing the
// secret (WU-506). Returns backend "local" when no S3 config is set.
func handleOrgStorageStatus(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	secret, err := ac.Tx.FindOrgSecretByKey(ctx, sqlc.FindOrgSecretByKeyParams{OrgID: ac.Org, Key: storageConfigKey})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return map[string]any{"org_id": ac.Org, "backend": "local"}, nil
		}
		return nil, fmt.Errorf("org.storage.status: %w", err)
	}
	plain, err := tenant.Decrypt(ac.SecretKey, secret.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("org.storage.status: decrypt: %w", err)
	}
	cfg, err := storage.ParseS3Config([]byte(plain))
	if err != nil {
		return nil, fmt.Errorf("org.storage.status: parse: %w", err)
	}
	// Mask the secret key in the response.
	cfg.SecretAccessKey = "••••"
	return map[string]any{
		"org_id":        ac.Org,
		"backend":       "s3",
		"storage":       cfg,
		"configured_at": secret.CreatedAt,
	}, nil
}

func init() {
	Register(Definition{
		Name:       "org.storage.configure",
		Impact:     ImpactHigh,
		Permission: "org.storage.configure",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleOrgStorageConfigure,
	})
	Register(Definition{
		Name:       "org.storage.status",
		Impact:     ImpactRead,
		Permission: "org.storage.status",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleOrgStorageStatus,
	})
}
