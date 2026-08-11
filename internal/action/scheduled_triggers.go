package action

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/schedule"
)

// scheduledTriggerInput is the common input to trigger.create/update.
type scheduledTriggerInput struct {
	ID        string `json:"id,omitempty"`
	OrgID     string `json:"org_id"`
	ProjectID string `json:"project_id"`
	AgentID   string `json:"agent_id"`
	CronExpr  string `json:"cron_expr"`
	Prompt    string `json:"prompt,omitempty"`
	Enabled   int64  `json:"enabled,omitempty"`
}

// handleScheduledTriggerCreate creates a scheduled_triggers row (WU-309):
// a cron expression + agent + prompt that periodically enqueues an agent run
// for a project. The cron is validated and next_at is computed at creation.
func handleScheduledTriggerCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input scheduledTriggerInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("trigger.create: bad input: %w", err)
	}
	if input.AgentID == "" || input.CronExpr == "" {
		return nil, fmt.Errorf("trigger.create: agent_id and cron_expr are required")
	}

	// Validate cron and compute the first fire time.
	nextAt, err := schedule.NextAt(input.CronExpr, time.Now())
	if err != nil {
		return nil, fmt.Errorf("trigger.create: invalid cron: %w", err)
	}

	id := newID()
	t, err := ac.Tx.CreateScheduledTrigger(ctx, sqlc.CreateScheduledTriggerParams{
		ID:        id,
		OrgID:     ac.Org,
		ProjectID: input.ProjectID,
		AgentID:   input.AgentID,
		CronExpr:  input.CronExpr,
		Prompt:    input.Prompt,
		NextAt:    nextAt,
		Enabled:   1,
	})
	if err != nil {
		return nil, fmt.Errorf("trigger.create: %w", err)
	}
	return t, nil
}

// handleScheduledTriggerUpdate edits a trigger's cron/agent/prompt/enabled and
// recomputes next_at (pause/resume is enabled=0/1 — WU-309).
func handleScheduledTriggerUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input scheduledTriggerInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("trigger.update: bad input: %w", err)
	}

	// Recompute next_at if enabled and the cron changed. When paused we clear
	// next_at so the scheduler skips the row (enabled=0 gate).
	nextAt := ""
	if input.Enabled != 0 && input.CronExpr != "" {
		n, err := schedule.NextAt(input.CronExpr, time.Now())
		if err != nil {
			return nil, fmt.Errorf("trigger.update: invalid cron: %w", err)
		}
		nextAt = n
	}

	if err := ac.Tx.UpdateScheduledTrigger(ctx, sqlc.UpdateScheduledTriggerParams{
		CronExpr:  input.CronExpr,
		Prompt:    input.Prompt,
		AgentID:   input.AgentID,
		Enabled:   input.Enabled,
		NextAt:    nextAt,
		UpdatedAt: time.Now().UTC().Format(timeFormat),
		ID:        input.ID,
		OrgID:     ac.Org,
	}); err != nil {
		return nil, fmt.Errorf("trigger.update: %w", err)
	}
	t, err := ac.Tx.FindScheduledTriggerByID(ctx, sqlc.FindScheduledTriggerByIDParams{ID: input.ID, OrgID: ac.Org})
	if err != nil {
		return nil, fmt.Errorf("trigger.update: lookup: %w", err)
	}
	return t, nil
}

// handleScheduledTriggerDelete removes a scheduled trigger (WU-309).
func handleScheduledTriggerDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("trigger.delete: bad input: %w", err)
	}
	if err := ac.Tx.DeleteScheduledTrigger(ctx, sqlc.DeleteScheduledTriggerParams{ID: input.ID, OrgID: ac.Org}); err != nil {
		return nil, fmt.Errorf("trigger.delete: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

// handleScheduledTriggerList lists the project's scheduled triggers (WU-309).
func handleScheduledTriggerList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	triggers, err := ac.Tx.ListScheduledTriggersByProject(ctx, sqlc.ListScheduledTriggersByProjectParams{
		OrgID:     ac.Org,
		ProjectID: ac.Proj,
	})
	if err != nil {
		return nil, fmt.Errorf("trigger.list: %w", err)
	}
	return triggers, nil
}

func init() {
	Register(Definition{
		Name:       "trigger.create",
		Impact:     ImpactHigh,
		Permission: "trigger.create",
		Scope:      ScopeProject,
		Input: ObjectSchema{Fields: []Field{
			{Name: "project_id", Kind: KindString, Required: true},
			{Name: "agent_id", Kind: KindString, Required: true},
			{Name: "cron_expr", Kind: KindString, Required: true},
			{Name: "prompt", Kind: KindString, Required: false},
		}},
		Handle: handleScheduledTriggerCreate,
	})
	Register(Definition{
		Name:       "trigger.update",
		Impact:     ImpactHigh,
		Permission: "trigger.update",
		Scope:      ScopeProject,
		Input: ObjectSchema{Fields: []Field{
			{Name: "id", Kind: KindString, Required: true},
			{Name: "project_id", Kind: KindString, Required: false},
			{Name: "agent_id", Kind: KindString, Required: false},
			{Name: "cron_expr", Kind: KindString, Required: false},
			{Name: "prompt", Kind: KindString, Required: false},
			{Name: "enabled", Kind: KindNumber, Required: false},
		}},
		Handle: handleScheduledTriggerUpdate,
	})
	Register(Definition{
		Name:       "trigger.delete",
		Impact:     ImpactHigh,
		Permission: "trigger.delete",
		Scope:      ScopeProject,
		Input: ObjectSchema{Fields: []Field{
			{Name: "id", Kind: KindString, Required: true},
		}},
		Handle: handleScheduledTriggerDelete,
	})
	Register(Definition{
		Name:       "trigger.list",
		Impact:     ImpactRead,
		Permission: "trigger.list",
		Scope:      ScopeProject,
		Input:      nil,
		Handle:     handleScheduledTriggerList,
	})
}
