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
	}

	if len(allGrants) == 0 {
		return false, nil
	}

	return checkPermission(requiredPermission, allGrants), nil
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
	return a.inner.Allow(ctx, ac.Actor.ID, ac.Org, ac.Team, ac.Proj, def.Permission)
}

// --- Tests ---

// checkPermission is exported for testing.
func CheckPermission(required string, grants []string) bool {
	return checkPermission(required, grants)
}
