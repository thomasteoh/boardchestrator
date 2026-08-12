package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// --- Action definitions for outbound webhooks (WU-404) ---
type webhookCreateInput struct {
	OrgID       string   `json:"org_id"`
	TeamID      string   `json:"team_id,omitempty"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Secret      string   `json:"secret,omitempty"`
	EventFilter []string `json:"event_filter,omitempty"`
}

type webhookUpdateInput struct {
	ID          string   `json:"id"`
	OrgID       string   `json:"org_id"`
	TeamID      string   `json:"team_id,omitempty"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Secret      string   `json:"secret,omitempty"`
	EventFilter []string `json:"event_filter,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
}

type webhookDeleteInput struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`
}

type webhookListInput struct {
	OrgID  string `json:"org_id"`
	TeamID string `json:"team_id,omitempty"`
}

func init() {
	Register(Definition{
		Name:       "webhook.create",
		Impact:     ImpactHigh,
		Permission: "webhook.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleWebhookCreate,
	})
	Register(Definition{
		Name:       "webhook.update",
		Impact:     ImpactLow,
		Permission: "webhook.update",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleWebhookUpdate,
	})
	Register(Definition{
		Name:       "webhook.delete",
		Impact:     ImpactHigh,
		Permission: "webhook.delete",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleWebhookDelete,
	})
	Register(Definition{
		Name:       "webhook.list",
		Impact:     ImpactRead,
		Permission: "webhook.list",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleWebhookList,
	})
}

func handleWebhookCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input webhookCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("webhook.create: %w", err)
	}
	if input.Name == "" || input.URL == "" {
		return nil, fmt.Errorf("webhook.create: name and url are required")
	}
	org := ac.Org
	if input.OrgID != "" {
		org = input.OrgID
	}
	// A team-scoped webhook must name an existing team in the org.
	var teamID sql.NullString
	if input.TeamID != "" {
		team, err := ac.Tx.FindTeamByID(ctx, sqlc.FindTeamByIDParams{ID: input.TeamID, OrgID: org})
		if err != nil {
			return nil, fmt.Errorf("webhook.create: team: %w", err)
		}
		teamID = sql.NullString{String: team.ID, Valid: true}
	}
	filter, _ := json.Marshal(input.EventFilter)
	wh, err := ac.Tx.CreateWebhook(ctx, sqlc.CreateWebhookParams{
		ID:          newID(),
		OrgID:       org,
		TeamID:      teamID,
		Name:        input.Name,
		Url:         input.URL,
		Secret:      input.Secret,
		EventFilter: string(filter),
		Enabled:     1,
	})
	if err != nil {
		return nil, fmt.Errorf("webhook.create: %w", err)
	}
	return webhookJSON(wh), nil
}

func handleWebhookUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input webhookUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("webhook.update: %w", err)
	}
	org := ac.Org
	if input.OrgID != "" {
		org = input.OrgID
	}
	existing, err := ac.Tx.FindWebhookByID(ctx, sqlc.FindWebhookByIDParams{ID: input.ID, OrgID: org})
	if err != nil {
		return nil, fmt.Errorf("webhook.update: not found: %w", err)
	}
	name, url := existing.Name, existing.Url
	if input.Name != "" {
		name = input.Name
	}
	if input.URL != "" {
		url = input.URL
	}
	secret := existing.Secret
	if input.Secret != "" {
		secret = input.Secret
	}
	filter := existing.EventFilter
	if input.EventFilter != nil {
		b, _ := json.Marshal(input.EventFilter)
		filter = string(b)
	}
	enabled := existing.Enabled
	if input.Enabled != nil {
		if *input.Enabled {
			enabled = 1
		} else {
			enabled = 0
		}
	}
	if err := ac.Tx.UpdateWebhook(ctx, sqlc.UpdateWebhookParams{
		Name: name, Url: url, Secret: secret, EventFilter: filter, Enabled: enabled,
		ID: input.ID, OrgID: org,
		UpdatedAt: time.Now().UTC().Format(timeFormat),
	}); err != nil {
		return nil, fmt.Errorf("webhook.update: %w", err)
	}
	wh, err := ac.Tx.FindWebhookByID(ctx, sqlc.FindWebhookByIDParams{ID: input.ID, OrgID: org})
	if err != nil {
		return nil, fmt.Errorf("webhook.update: re-read: %w", err)
	}
	return webhookJSON(wh), nil
}

func handleWebhookDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input webhookDeleteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("webhook.delete: %w", err)
	}
	org := ac.Org
	if input.OrgID != "" {
		org = input.OrgID
	}
	if err := ac.Tx.DeleteWebhook(ctx, sqlc.DeleteWebhookParams{ID: input.ID, OrgID: org}); err != nil {
		return nil, fmt.Errorf("webhook.delete: %w", err)
	}
	return map[string]any{"id": input.ID, "deleted": true}, nil
}

func handleWebhookList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input webhookListInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("webhook.list: %w", err)
	}
	org := ac.Org
	if input.OrgID != "" {
		org = input.OrgID
	}
	var whs []sqlc.Webhook
	var err error
	if input.TeamID != "" {
		whs, err = ac.Tx.ListWebhooksByTeam(ctx, sqlc.ListWebhooksByTeamParams{OrgID: org, TeamID: sql.NullString{String: input.TeamID, Valid: true}})
	} else {
		whs, err = ac.Tx.ListWebhooksByOrg(ctx, org)
	}
	if err != nil {
		return nil, fmt.Errorf("webhook.list: %w", err)
	}
	out := make([]map[string]any, 0, len(whs))
	for _, wh := range whs {
		out = append(out, webhookJSON(wh))
	}
	return map[string]any{"webhooks": out}, nil
}

func webhookJSON(wh sqlc.Webhook) map[string]any {
	return map[string]any{
		"id": wh.ID, "org_id": wh.OrgID, "team_id": wh.TeamID.String,
		"name": wh.Name, "url": wh.Url, "enabled": wh.Enabled == 1,
		"event_filter": wh.EventFilter, "created_at": wh.CreatedAt, "updated_at": wh.UpdatedAt,
	}
}

// timeNowUTC returns the UTC RFC3339 timestamp used by action writes.
