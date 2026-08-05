package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// userThemeUpdateInput is the input for user.theme.update.
type userThemeUpdateInput struct {
	Theme string `json:"theme"`
}

// userTimezoneUpdateInput is the input for user.timezone.update.
type userTimezoneUpdateInput struct {
	Timezone string `json:"timezone"`
}

// sessionRevokeInput is the input for session.revoke.
type sessionRevokeInput struct {
	TokenHash string `json:"token_hash"`
}

func init() {
	Register(Definition{
		Name:       "user.theme.update",
		Impact:     ImpactLow,
		Permission: "user.theme.update",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleUserThemeUpdate,
	})
	Register(Definition{
		Name:       "user.timezone.update",
		Impact:     ImpactLow,
		Permission: "user.timezone.update",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleUserTimezoneUpdate,
	})
	Register(Definition{
		Name:       "session.revoke",
		Impact:     ImpactLow,
		Permission: "session.revoke",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleSessionRevoke,
	})
}

// RegisterUserActions is exported so cmd/bc/serve.go can ensure the action package's init() runs.
func RegisterUserActions() {}

func handleUserThemeUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input userThemeUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("user.theme.update: %w", err)
	}
	if err := ac.Tx.UpdateUserTheme(ctx, sqlc.UpdateUserThemeParams{
		Theme: input.Theme,
		ID:    ac.Actor.ID,
	}); err != nil {
		return nil, fmt.Errorf("user.theme.update: %w", err)
	}
	return map[string]string{"status": "ok"}, nil
}

func handleUserTimezoneUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input userTimezoneUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("user.timezone.update: %w", err)
	}
	if err := ac.Tx.UpdateUserTimezone(ctx, sqlc.UpdateUserTimezoneParams{
		Timezone: input.Timezone,
		ID:       ac.Actor.ID,
	}); err != nil {
		return nil, fmt.Errorf("user.timezone.update: %w", err)
	}
	return map[string]string{"status": "ok"}, nil
}

func handleSessionRevoke(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input sessionRevokeInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("session.revoke: %w", err)
	}
	if err := ac.Tx.DeleteSession(ctx, input.TokenHash); err != nil {
		return nil, fmt.Errorf("session.revoke: %w", err)
	}
	return map[string]string{"status": "ok"}, nil
}
