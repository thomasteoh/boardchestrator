// Package perm implements the permission engine per SPEC §6.
package perm

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Checker resolves effective grants from the DB.
type Checker struct {
	q *sqlc.Queries
}

// NewChecker builds a Checker over the sqlc queries.
func NewChecker(d *sql.DB) *Checker {
	return &Checker{q: sqlc.New(d)}
}

// PlatformOrg is the sentinel org that holds platform-level roles (SPEC §6:
// roles with org_id NULL act as platform defaults). Platform-scope actions
// (org.create, pricing, providers, ...) are granted via memberships in this
// org; the membership walk falls back to it when orgID == "".
const PlatformOrg = "00000000000000000000000000000000"

// PlatformOwnerRole is the sentinel Org Owner role seeded on the platform org
// (migrations/0005_roles.up.sql, grants ["*"]). Platform admins hold this role
// via their sentinel-org membership.
const PlatformOwnerRole = "00000000000000000000000000000000"

// Allow resolves whether actor has the required permission.
func (c *Checker) Allow(ctx context.Context, actorID string, orgID, teamID, projectID string, requiredPermission string) (bool, error) {
	if requiredPermission == "" {
		return true, nil
	}

	var allGrants []string

	// Walk scope hierarchy: project → team → org.
	if projectID != "" {
		grants, err := c.grantsForScope(ctx, "project", projectID, orgID, actorID)
		if err != nil {
			return false, err
		}
		allGrants = append(allGrants, grants...)
	}
	if teamID != "" {
		grants, err := c.grantsForScope(ctx, "team", teamID, orgID, actorID)
		if err != nil {
			return false, err
		}
		allGrants = append(allGrants, grants...)
	}
	if orgID != "" {
		grants, err := c.grantsForScope(ctx, "org", orgID, orgID, actorID)
		if err != nil {
			return false, err
		}
		allGrants = append(allGrants, grants...)
	} else {
		// Platform-scope action: grants come from the platform sentinel org
		// (platform admins hold an Org Owner membership there).
		grants, err := c.grantsForScope(ctx, "org", PlatformOrg, PlatformOrg, actorID)
		if err != nil {
			return false, err
		}
		allGrants = append(allGrants, grants...)
	}

	if len(allGrants) == 0 {
		return false, nil
	}

	return checkPermission(requiredPermission, allGrants), nil
}

// AllowAgent resolves whether an agent actor has the required permission.
// Per SPEC §6, an agent's effective permission set is the intersection of its
// role grants and the union of allowed_actions across its attached skills:
//
//	effective = role grants ∩ union(attached skills' allowed_actions)
//
// The agent must be a member of the org to act (memberships carry its role).
func (c *Checker) AllowAgent(ctx context.Context, agentID, orgID string, requiredPermission string) (bool, error) {
	if requiredPermission == "" {
		return true, nil
	}

	// Role grants come from the agent's membership role in the org.
	grants, err := c.agentRoleGrants(ctx, agentID, orgID)
	if err != nil {
		return false, err
	}
	if len(grants) == 0 {
		return false, nil
	}

	// Union of allowed_actions across attached skills.
	skillUnion, err := c.agentSkillActions(ctx, agentID, orgID)
	if err != nil {
		return false, err
	}

	effective := intersectGrants(grants, skillUnion)
	return checkPermission(requiredPermission, effective), nil
}

// agentRoleGrants resolves the grants of the org role an agent holds via its
// membership row (actor_type=agent). Returns nil if the agent has no role.
func (c *Checker) agentRoleGrants(ctx context.Context, agentID, orgID string) ([]string, error) {
	rows, err := c.q.FindMemberships(ctx, sqlc.FindMembershipsParams{
		OrgID:        orgID,
		ActorType:    "agent",
		ActorID:      agentID,
		ResourceType: "org",
		ResourceID:   orgID,
	})
	if err != nil {
		return nil, fmt.Errorf("perm: agent memberships: %w", err)
	}
	var allGrants []string
	for _, r := range rows {
		if !r.RoleID.Valid {
			continue
		}
		grants, err := c.roleGrants(ctx, r.RoleID.String, r.OrgID)
		if err != nil {
			return nil, err
		}
		allGrants = append(allGrants, grants...)
	}
	return allGrants, nil
}

// agentSkillActions returns the union of allowed_actions across the agent's
// attached skills.
func (c *Checker) agentSkillActions(ctx context.Context, agentID, orgID string) ([]string, error) {
	rows, err := c.q.ListAgentSkillActions(ctx, sqlc.ListAgentSkillActionsParams{
		AgentID: agentID,
		OrgID:   sql.NullString{String: orgID, Valid: orgID != ""},
	})
	if err != nil {
		return nil, fmt.Errorf("perm: agent skill actions: %w", err)
	}
	var union []string
	for _, jsonRow := range rows {
		var actions []string
		if err := json.Unmarshal([]byte(jsonRow), &actions); err != nil {
			continue
		}
		union = append(union, actions...)
	}
	return union, nil
}

// intersectGrants returns the set of role grants that are also in the skill
// union. A wildcard grant (e.g. "task.*") is retained only if the skill union
// has a matching concrete action for it.
func intersectGrants(grants, union []string) []string {
	// A grant g survives if the skill union contains at least one action that
	// g covers: checkPermission(unionAction, []string{g}) — union action as
	// required, g as the grant.
	var out []string
	for _, g := range grants {
		for _, u := range union {
			if checkPermission(u, []string{g}) {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

func (c *Checker) grantsForScope(ctx context.Context, scopeType, scopeID, orgID, actorID string) ([]string, error) {
	rows, err := c.q.FindMemberships(ctx, sqlc.FindMembershipsParams{
		OrgID:        orgID,
		ActorType:    "user",
		ActorID:      actorID,
		ResourceType: scopeType,
		ResourceID:   scopeID,
	})
	if err != nil {
		return nil, fmt.Errorf("perm: memberships %s/%s/%s: %w", scopeType, scopeID, actorID, err)
	}

	var allGrants []string
	for _, r := range rows {
		if !r.RoleID.Valid {
			continue
		}
		grants, err := c.roleGrants(ctx, r.RoleID.String, r.OrgID)
		if err != nil {
			return nil, err
		}
		allGrants = append(allGrants, grants...)
	}
	return allGrants, nil
}

func (c *Checker) roleGrants(ctx context.Context, roleID, orgID string) ([]string, error) {
	role, err := c.q.FindRoleByID(ctx, sqlc.FindRoleByIDParams{ID: roleID, OrgID: orgID})
	if err != nil {
		return nil, fmt.Errorf("perm: find role %s: %w", roleID, err)
	}
	var grants []string
	if err := json.Unmarshal([]byte(role.GrantsJson), &grants); err != nil {
		return nil, fmt.Errorf("perm: parse grants: %w", err)
	}
	return grants, nil
}

// checkPermission checks if required is covered by any grant.
func checkPermission(required string, grants []string) bool {
	for _, g := range grants {
		if g == required {
			return true
		}
		if strings.HasSuffix(g, ".*") {
			prefix := strings.TrimSuffix(g, ".*")
			if strings.HasPrefix(required, prefix+".") {
				return true
			}
		}
		if g == "*" {
			return true
		}
	}
	return false
}

// AllowAll returns true for any permission — used for system roles with "*".
func AllowAll() bool { return true }

// DenyAll returns false for any permission — default for no memberships.
func DenyAll() bool { return false }

// --- action.PermissionChecker adapter ---

// CheckerAdapter wraps Checker to implement action.PermissionChecker.
type CheckerAdapter struct {
	inner *Checker
}

// NewCheckerAdapter builds an adapter that satisfies action.PermissionChecker.
func NewCheckerAdapter(d *sql.DB) *CheckerAdapter {
	return &CheckerAdapter{inner: NewChecker(d)}
}

// Allow implements action.PermissionChecker.
func (a *CheckerAdapter) Allow(ctx context.Context, ac action.ActionCtx, def action.Definition) (bool, error) {
	// Trusted system integration principals (GitHub webhook bridge, WU-405)
	// bypass grant checks — they run configured transitions only.
	if ac.Actor.Type == action.ActorService {
		return true, nil
	}
	// Agent actors resolve via role-grants ∩ attached-skills intersection
	// (SPEC §6); user/apikey actors via the standard membership walk.
	if ac.Actor.Type == action.ActorAgent {
		return a.inner.AllowAgent(ctx, ac.Actor.ID, ac.Org, def.Permission)
	}
	return a.inner.Allow(ctx, ac.Actor.ID, ac.Org, ac.Team, ac.Proj, def.Permission)
}

// --- Tests ---

// checkPermission is exported for testing.
func CheckPermission(required string, grants []string) bool {
	return checkPermission(required, grants)
}
