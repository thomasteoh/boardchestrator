package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// githubConnectInput carries the connection source. source "oauth" reuses the
// SSO identity token captured at GitHub login (identities.token_enc); source
// "pat" stores a user-entered personal access token, encrypted at rest.
type githubConnectInput struct {
	Source string `json:"source"` // oauth | pat
	Token  string `json:"token,omitempty"`
	Login  string `json:"login,omitempty"`
}

func init() {
	Register(Definition{
		Name:       "github.connect",
		Impact:     ImpactLow,
		Permission: "github.connect",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleGithubConnect,
	})
	Register(Definition{
		Name:       "github.disconnect",
		Impact:     ImpactLow,
		Permission: "github.disconnect",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleGithubDisconnect,
	})
	Register(Definition{
		Name:       "github.status",
		Impact:     ImpactRead,
		Permission: "github.status",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleGithubStatus,
	})
}

func handleGithubConnect(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input githubConnectInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("github.connect: %w", err)
	}

	provider := "oauth"
	tokenEnc := ""
	login := input.Login

	switch input.Source {
	case "oauth":
		// Reuse the SSO identity token if present (identities.token_enc,
		// captured at GitHub login).
		ident, err := ac.Tx.FindIdentityByUserAndProvider(ctx, sqlc.FindIdentityByUserAndProviderParams{
			UserID: ac.Actor.ID, Provider: "github",
		})
		if err != nil || len(ident.TokenEnc) == 0 {
			return nil, fmt.Errorf("github.connect: no SSO GitHub token — sign in via GitHub, or connect with a PAT")
		}
		tokenEnc = string(ident.TokenEnc)
		if login == "" {
			login = "oauth"
		}
	case "pat":
		if input.Token == "" {
			return nil, fmt.Errorf("github.connect: PAT token required")
		}
		if len(ac.SecretKey) == 0 {
			return nil, fmt.Errorf("github.connect: encryption key not configured")
		}
		enc, err := tenant.Encrypt(ac.SecretKey, input.Token)
		if err != nil {
			return nil, fmt.Errorf("github.connect: encrypt: %w", err)
		}
		tokenEnc = enc
		provider = "pat"
	default:
		return nil, fmt.Errorf("github.connect: unknown source %q", input.Source)
	}

	conn, err := ac.Tx.UpsertGithubConnection(ctx, sqlc.UpsertGithubConnectionParams{
		UserID:    ac.Actor.ID,
		Provider:  provider,
		TokenEnc:  tokenEnc,
		Login:     login,
		UpdatedAt: time.Now().UTC().Format(timeFormat),
	})
	if err != nil {
		return nil, fmt.Errorf("github.connect: %w", err)
	}
	return githubConnectionJSON(conn), nil
}

func handleGithubDisconnect(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	if err := ac.Tx.DeleteGithubConnection(ctx, ac.Actor.ID); err != nil {
		return nil, fmt.Errorf("github.disconnect: %w", err)
	}
	return map[string]any{"connected": false, "deleted": true}, nil
}

func handleGithubStatus(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	conn, err := ac.Tx.FindGithubConnection(ctx, ac.Actor.ID)
	if err != nil {
		// No connection: not connected.
		if err == sql.ErrNoRows {
			return map[string]any{"connected": false, "provider": ""}, nil
		}
		return nil, fmt.Errorf("github.status: %w", err)
	}
	return map[string]any{
		"connected":  true,
		"provider":   conn.Provider,
		"login":      conn.Login,
		"created_at": conn.CreatedAt,
		"updated_at": conn.UpdatedAt,
	}, nil
}

func githubConnectionJSON(conn sqlc.GithubConnection) map[string]any {
	return map[string]any{
		"connected":  true,
		"provider":   conn.Provider,
		"login":      conn.Login,
		"created_at": conn.CreatedAt,
		"updated_at": conn.UpdatedAt,
	}
}
