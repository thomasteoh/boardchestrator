// Package agentrt implements the agent run engine (SPEC §10): run lifecycle,
// labelled-cascade context assembly, the registry-derived tool loop filtered
// by the agent's effective permission set, step caps, cancellation, and
// retry→notify failure handling.
package agentrt

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// EffectivePerms resolves an agent's effective permission set per SPEC §6:
// effective = role grants ∩ union of attached skills' allowed_actions.
// It returns the set of action names the agent may perform.
func EffectivePerms(ctx context.Context, q *sqlc.Queries, agent sqlc.Agent) (map[string]bool, error) {
	// 1. Role grants from the agent's role_id (if any).
	grants := map[string]bool{}
	orgID := agent.OrgID.String
	if agent.RoleID.Valid && agent.RoleID.String != "" {
		role, err := q.FindRoleByID(ctx, sqlc.FindRoleByIDParams{
			ID:    agent.RoleID.String,
			OrgID: orgID,
		})
		if err != nil {
			return nil, fmt.Errorf("run: find agent role: %w", err)
		}
		var perms []string
		if err := json.Unmarshal([]byte(role.GrantsJson), &perms); err != nil {
			return nil, fmt.Errorf("run: parse role grants: %w", err)
		}
		for _, p := range perms {
			grants[p] = true
		}
	}

	// 2. Union of attached skills' allowed_actions.
	skillActions := map[string]bool{}
	skills, err := q.ListAgentSkillsWithActions(ctx, sqlc.ListAgentSkillsWithActionsParams{
		AgentID: agent.ID,
		OrgID:   sql.NullString{String: orgID, Valid: orgID != ""},
	})
	if err != nil {
		return nil, fmt.Errorf("run: list agent skills: %w", err)
	}
	for _, s := range skills {
		var acts []string
		if err := json.Unmarshal([]byte(s.AllowedActionsJson), &acts); err != nil {
			return nil, fmt.Errorf("run: parse skill %s allowed_actions: %w", s.Name, err)
		}
		for _, a := range acts {
			skillActions[a] = true
		}
	}

	// 3. Intersection. With no role grants the agent has no permissions
	// (deny-by-default). A grant must appear in both role and at least one
	// skill to be effective.
	effective := map[string]bool{}
	for g := range grants {
		if skillActions[g] {
			effective[g] = true
		}
	}
	return effective, nil
}

// grantAllows reports whether an effective permission set covers a required
// action, honouring the "*" and "prefix.*" wildcard forms (mirrors perm).
func grantAllows(required string, effective map[string]bool) bool {
	if effective[required] || effective["*"] {
		return true
	}
	// prefix.* wildcard
	for g := range effective {
		if len(g) > 2 && g[len(g)-2:] == ".*" {
			prefix := g[:len(g)-2]
			if len(required) > len(prefix) && required[:len(prefix)] == prefix && required[len(prefix)] == '.' {
				return true
			}
		}
	}
	return false
}

// agentPermChecker is an action.PermissionChecker that resolves an agent
// actor's effective permissions from the DB. It is used by the run engine's
// own Dispatcher so agent tool calls are gated by the same effective set the
// tool list was filtered with.
type agentPermChecker struct {
	db *sql.DB
}

func (c agentPermChecker) Allow(ctx context.Context, ac action.ActionCtx, def action.Definition) (bool, error) {
	if ac.Actor.Type != action.ActorAgent {
		// Non-agent actors on the engine's dispatcher are platform/system
		// calls; the engine only dispatches as the agent. Allow reads.
		return def.Impact == action.ImpactRead, nil
	}
	q := sqlc.New(c.db)
	agent, err := q.FindAgentByID(ctx, ac.Actor.ID)
	if err != nil {
		return false, fmt.Errorf("run: find agent %s: %w", ac.Actor.ID, err)
	}
	eff, err := EffectivePerms(ctx, q, agent)
	if err != nil {
		return false, err
	}
	if def.Permission == "" {
		return true, nil
	}
	return grantAllows(def.Permission, eff), nil
}
