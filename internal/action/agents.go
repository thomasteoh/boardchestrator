package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

type agentCreateInput struct {
	OrgID      string `json:"org_id"`
	Name       string `json:"name"`
	ProviderID string `json:"provider_id"`
	Model      string `json:"model"`
}

type agentUpdateInput struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	ProviderID      string `json:"provider_id"`
	Model           string `json:"model"`
	Context         string `json:"context"`
	RoleID          string `json:"role_id"`
	RetryMax        int    `json:"retry_max"`
	BackoffSecs     int    `json:"backoff_secs"`
	RunsPerHour     int    `json:"runs_per_hour"`
	TokenBudget     int    `json:"token_budget"`
	ApprovalPolicy  string `json:"approval_policy"`
	Active          bool   `json:"active"`
}

type agentDeleteInput struct {
	ID string `json:"id"`
}

type agentListInput struct {
	OrgID string `json:"org_id"`
}

type agentListTemplatesInput struct{}

type agentSkillAttachInput struct {
	AgentID string `json:"agent_id"`
	SkillID string `json:"skill_id"`
}

type agentSkillDetachInput struct {
	AgentID string `json:"agent_id"`
	SkillID string `json:"skill_id"`
}

func init() {
	Register(Definition{
		Name:       "agent.create",
		Impact:     ImpactHigh,
		Permission: "agent.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAgentCreate,
	})
	Register(Definition{
		Name:       "agent.update",
		Impact:     ImpactHigh,
		Permission: "agent.update",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAgentUpdate,
	})
	Register(Definition{
		Name:       "agent.delete",
		Impact:     ImpactHigh,
		Permission: "agent.delete",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAgentDelete,
	})
	Register(Definition{
		Name:       "agent.list",
		Impact:     ImpactRead,
		Permission: "agent.list",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAgentList,
	})
	Register(Definition{
		Name:       "agent.list-templates",
		Impact:     ImpactRead,
		Permission: "agent.list-templates",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAgentListTemplates,
	})
	Register(Definition{
		Name:       "agent.skill-attach",
		Impact:     ImpactHigh,
		Permission: "agent.update",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAgentSkillAttach,
	})
	Register(Definition{
		Name:       "agent.skill-detach",
		Impact:     ImpactHigh,
		Permission: "agent.update",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleAgentSkillDetach,
	})
}

func RegisterAgentActions() {}

func handleAgentCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input agentCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("agent.create: %w", err)
	}
	id := newID()
	_, err := ac.Tx.CreateAgent(ctx, sqlc.CreateAgentParams{
		ID:                 id,
		OrgID:              sql.NullString{String: input.OrgID, Valid: input.OrgID != ""},
		TemplateID:         sql.NullString{Valid: false},
		Name:               input.Name,
		ProviderID:         input.ProviderID,
		Model:              input.Model,
		Context:            "",
		RoleID:             sql.NullString{Valid: false},
		RetryMax:           3,
		BackoffSecs:        30,
		RunsPerHour:        20,
		TokenBudget:        50000,
		ApprovalPolicyJson: `{"low":"auto","read":"auto","high":"require"}`,
		Active:             1,
	})
	if err != nil {
		return nil, fmt.Errorf("agent.create: %w", err)
	}
	return map[string]string{"id": id}, nil
}

func handleAgentUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input agentUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("agent.update: %w", err)
	}
	active := int64(0)
	if input.Active {
		active = 1
	}
	roleID := sql.NullString{Valid: false}
	if input.RoleID != "" {
		roleID = sql.NullString{String: input.RoleID, Valid: true}
	}
	_, err := ac.Tx.UpdateAgent(ctx, sqlc.UpdateAgentParams{
		Name:               input.Name,
		ProviderID:         input.ProviderID,
		Model:              input.Model,
		Context:            input.Context,
		RoleID:             roleID,
		RetryMax:           int64(input.RetryMax),
		BackoffSecs:        int64(input.BackoffSecs),
		RunsPerHour:        int64(input.RunsPerHour),
		TokenBudget:        int64(input.TokenBudget),
		ApprovalPolicyJson: input.ApprovalPolicy,
		Active:             active,
		ID:                 input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("agent.update: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleAgentDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input agentDeleteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("agent.delete: %w", err)
	}
	if err := ac.Tx.DeleteAgent(ctx, input.ID); err != nil {
		return nil, fmt.Errorf("agent.delete: %w", err)
	}
	return nil, nil
}

func handleAgentList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input agentListInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("agent.list: %w", err)
	}
	agents, err := ac.Tx.ListAgentsByOrg(ctx, sql.NullString{String: input.OrgID, Valid: input.OrgID != ""})
	if err != nil {
		return nil, fmt.Errorf("agent.list: %w", err)
	}
	return agents, nil
}

func handleAgentListTemplates(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	agents, err := ac.Tx.ListAgents(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent.list-templates: %w", err)
	}
	// Filter to platform templates (org_id IS NULL)
	var templates []sqlc.Agent
	for _, a := range agents {
		if !a.OrgID.Valid {
			templates = append(templates, a)
		}
	}
	return templates, nil
}

func handleAgentSkillAttach(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input agentSkillAttachInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("agent.skill-attach: %w", err)
	}
	if err := ac.Tx.CreateAgentSkill(ctx, sqlc.CreateAgentSkillParams{
		AgentID: input.AgentID,
		SkillID: input.SkillID,
	}); err != nil {
		return nil, fmt.Errorf("agent.skill-attach: %w", err)
	}
	return nil, nil
}

func handleAgentSkillDetach(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input agentSkillDetachInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("agent.skill-detach: %w", err)
	}
	if err := ac.Tx.DeleteAgentSkill(ctx, sqlc.DeleteAgentSkillParams{
		AgentID: input.AgentID,
		SkillID: input.SkillID,
	}); err != nil {
		return nil, fmt.Errorf("agent.skill-detach: %w", err)
	}
	return nil, nil
}
