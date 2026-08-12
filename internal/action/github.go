package action

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// --- Action definitions for GitHub integration config (WU-405) ---
type githubConfigInput struct {
	ProjectID     string          `json:"project_id"`
	Repo          string          `json:"repo"`
	Transitions   json.RawMessage `json:"transitions,omitempty"` // PR-state → status map
	WebhookSecret string          `json:"webhook_secret,omitempty"`
	Enabled       *bool           `json:"enabled,omitempty"`
}

func init() {
	Register(Definition{
		Name:       "github.config.upsert",
		Impact:     ImpactLow,
		Permission: "github.config.upsert",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleGithubConfigUpsert,
	})
	Register(Definition{
		Name:       "github.config.delete",
		Impact:     ImpactLow,
		Permission: "github.config.delete",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleGithubConfigDelete,
	})
}

func handleGithubConfigUpsert(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input githubConfigInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("github.config.upsert: %w", err)
	}
	proj := ac.Proj
	if input.ProjectID != "" {
		proj = input.ProjectID
	}
	if proj == "" {
		return nil, fmt.Errorf("github.config.upsert: project_id required")
	}
	if input.Repo == "" {
		return nil, fmt.Errorf("github.config.upsert: repo required")
	}
	// Transitions is a JSON map of PR-state → status; keep raw if provided.
	transitions := "{}"
	if len(input.Transitions) > 0 {
		b, _ := json.Marshal(input.Transitions)
		transitions = string(b)
	}
	enabled := int64(1)
	if input.Enabled != nil && !*input.Enabled {
		enabled = 0
	}
	cfg, err := ac.Tx.UpsertProjectGithub(ctx, sqlc.UpsertProjectGithubParams{
		ID:            "pg-" + newID(),
		ProjectID:     proj,
		Repo:          input.Repo,
		Transitions:   transitions,
		WebhookSecret: input.WebhookSecret,
		Enabled:       enabled,
		UpdatedAt:     time.Now().UTC().Format(timeFormat),
	})
	if err != nil {
		return nil, fmt.Errorf("github.config.upsert: %w", err)
	}
	return githubConfigJSON(cfg), nil
}

func handleGithubConfigDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		Repo string `json:"repo"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("github.config.delete: %w", err)
	}
	if input.Repo == "" {
		return nil, fmt.Errorf("github.config.delete: repo required")
	}
	if err := ac.Tx.DeleteProjectGithub(ctx, input.Repo); err != nil {
		return nil, fmt.Errorf("github.config.delete: %w", err)
	}
	return map[string]any{"repo": input.Repo, "deleted": true}, nil
}

func githubConfigJSON(cfg sqlc.ProjectGithub) map[string]any {
	return map[string]any{
		"id": cfg.ID, "project_id": cfg.ProjectID, "repo": cfg.Repo,
		"transitions": cfg.Transitions, "enabled": cfg.Enabled == 1,
		"created_at": cfg.CreatedAt, "updated_at": cfg.UpdatedAt,
	}
}
