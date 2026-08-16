package action

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/schedule"
)

type templateCreateInput struct {
	OrgID               string `json:"org_id"`
	ProjectID           string `json:"project_id"`
	Name                string `json:"name"`
	TitleTemplate       string `json:"title_template"`
	DescriptionTemplate string `json:"description_template"`
	Points              int    `json:"points"`
	Priority            int    `json:"priority"`
	Status              string `json:"status"`
	LabelsJSON          string `json:"labels_json"`
}

type templateUpdateInput struct {
	ID                  string `json:"id"`
	OrgID               string `json:"org_id"`
	Name                string `json:"name"`
	TitleTemplate       string `json:"title_template"`
	DescriptionTemplate string `json:"description_template"`
	Points              int    `json:"points"`
	Priority            int    `json:"priority"`
	Status              string `json:"status"`
	LabelsJSON          string `json:"labels_json"`
}

type templateCreateFromInput struct {
	OrgID      string `json:"org_id"`
	ProjectID  string `json:"project_id"`
	TemplateID string `json:"template_id"`
	Title      string `json:"title"`
}

type recurringCreateInput struct {
	OrgID      string `json:"org_id"`
	ProjectID  string `json:"project_id"`
	TemplateID string `json:"template_id"`
	CronExpr   string `json:"cron_expr"`
}

func init() {
	Register(Definition{
		Name:       "template.create",
		Impact:     ImpactLow,
		Permission: "template.create",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTemplateCreate,
	})
	Register(Definition{
		Name:       "template.update",
		Impact:     ImpactLow,
		Permission: "template.update",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTemplateUpdate,
	})
	Register(Definition{
		Name:       "template.create_from",
		Impact:     ImpactLow,
		Permission: "template.create_from",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTemplateCreateFrom,
	})
	Register(Definition{
		Name:       "template.delete",
		Impact:     ImpactLow,
		Permission: "template.delete",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTemplateDelete,
	})
	Register(Definition{
		Name:       "recurring.create",
		Impact:     ImpactLow,
		Permission: "recurring.create",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleRecurringCreate,
	})
	Register(Definition{
		Name:       "recurring.update",
		Impact:     ImpactLow,
		Permission: "recurring.update",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleRecurringUpdate,
	})
	Register(Definition{
		Name:       "recurring.delete",
		Impact:     ImpactLow,
		Permission: "recurring.delete",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleRecurringDelete,
	})
}

// --- Template handlers ---

func handleTemplateCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input templateCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("template.create: bad input: %w", err)
	}
	if input.Name == "" {
		return nil, fmt.Errorf("template.create: name is required")
	}

	id := newID()
	t, err := ac.Tx.CreateTemplate(ctx, sqlc.CreateTemplateParams{
		ID:                  id,
		OrgID:               input.OrgID,
		ProjectID:           input.ProjectID,
		Name:                input.Name,
		TitleTemplate:       input.TitleTemplate,
		DescriptionTemplate: input.DescriptionTemplate,
		Points:              int64(input.Points),
		Priority:            int64(input.Priority),
		Status:              input.Status,
		LabelsJson:          input.LabelsJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("template.create: %w", err)
	}

	return t, nil
}

func handleTemplateUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input templateUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("template.update: bad input: %w", err)
	}

	t, err := ac.Tx.UpdateTemplate(ctx, sqlc.UpdateTemplateParams{
		ID:                  input.ID,
		OrgID:               input.OrgID,
		Name:                input.Name,
		TitleTemplate:       input.TitleTemplate,
		DescriptionTemplate: input.DescriptionTemplate,
		Points:              int64(input.Points),
		Priority:            int64(input.Priority),
		Status:              input.Status,
		LabelsJson:          input.LabelsJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("template.update: %w", err)
	}

	return t, nil
}

func handleTemplateCreateFrom(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input templateCreateFromInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("template.create_from: bad input: %w", err)
	}

	t, err := ac.Tx.FindTemplate(ctx, sqlc.FindTemplateParams{
		ID:    input.TemplateID,
		OrgID: input.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("template.create_from: find template: %w", err)
	}

	taskID := newID()

	// Build title from template or provided title.
	title := t.TitleTemplate
	if title == "" {
		title = input.Title
	}

	// Create task using template fields.
	next, err := ac.Tx.NextTaskNum(ctx, input.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("template.create_from: next task num: %w", err)
	}
	key := fmt.Sprintf("%s-%d", projectKeyFromID(input.ProjectID), next)

	task, err := ac.Tx.CreateTask(ctx, sqlc.CreateTaskParams{
		ID:          taskID,
		ProjectID:   input.ProjectID,
		Title:       title,
		Description: t.DescriptionTemplate,
		Key:         key,
		KeyNum:      next,
		Points:      t.Points,
		Priority:    t.Priority,
		Status:      t.Status,
		DueAt:       "",
		SortOrder:   float64(next),
	})
	if err != nil {
		return nil, fmt.Errorf("template.create_from: %w", err)
	}

	return task, nil
}

func handleTemplateDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("template.delete: bad input: %w", err)
	}
	if err := ac.Tx.DeleteTemplate(ctx, sqlc.DeleteTemplateParams{
		ID:    input.ID,
		OrgID: input.OrgID,
	}); err != nil {
		return nil, fmt.Errorf("template.delete: %w", err)
	}
	return map[string]bool{"deleted": true}, nil
}

// --- Recurring rule handlers ---

func handleRecurringCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input recurringCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("recurring.create: bad input: %w", err)
	}

	// Validate cron expression and compute next_at.
	nextAt, err := schedule.NextAt(input.CronExpr, time.Now())
	if err != nil {
		return nil, fmt.Errorf("recurring.create: invalid cron: %w", err)
	}

	id := newID()
	r, err := ac.Tx.CreateRecurringRule(ctx, sqlc.CreateRecurringRuleParams{
		ID:         id,
		OrgID:      input.OrgID,
		ProjectID:  input.ProjectID,
		TemplateID: input.TemplateID,
		CronExpr:   input.CronExpr,
	})
	if err != nil {
		return nil, fmt.Errorf("recurring.create: %w", err)
	}

	if err := ac.Tx.UpdateRecurringNextAt(ctx, sqlc.UpdateRecurringNextAtParams{
		NextAt: nextAt,
		ID:     r.ID,
	}); err != nil {
		return nil, fmt.Errorf("recurring.create: set next_at: %w", err)
	}

	return r, nil
}

func handleRecurringUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		ID       string `json:"id"`
		OrgID    string `json:"org_id"`
		CronExpr string `json:"cron_expr"`
		Enabled  int64  `json:"enabled"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("recurring.update: bad input: %w", err)
	}

	r, err := ac.Tx.UpdateRecurringRule(ctx, sqlc.UpdateRecurringRuleParams{
		ID:       input.ID,
		OrgID:    input.OrgID,
		CronExpr: input.CronExpr,
		NextAt:   "",
		Enabled:  input.Enabled,
	})
	if err != nil {
		return nil, fmt.Errorf("recurring.update: %w", err)
	}

	// Recompute next_at if enabled and cron changed.
	if input.Enabled != 0 && input.CronExpr != "" {
		nextAt, err := schedule.NextAt(input.CronExpr, time.Now())
		if err != nil {
			return nil, fmt.Errorf("recurring.update: cron: %w", err)
		}
		if err := ac.Tx.UpdateRecurringNextAt(ctx, sqlc.UpdateRecurringNextAtParams{
			NextAt: nextAt,
			ID:     r.ID,
		}); err != nil {
			return nil, fmt.Errorf("recurring.update: set next_at: %w", err)
		}
	}

	return r, nil
}

func handleRecurringDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		ID    string `json:"id"`
		OrgID string `json:"org_id"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("recurring.delete: bad input: %w", err)
	}

	if err := ac.Tx.DeleteRecurringRule(ctx, sqlc.DeleteRecurringRuleParams{
		ID:    input.ID,
		OrgID: input.OrgID,
	}); err != nil {
		return nil, fmt.Errorf("recurring.delete: %w", err)
	}

	return map[string]bool{"deleted": true}, nil
}
