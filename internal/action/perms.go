package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// --- Role action definitions ---

type membershipCreateInput struct {
	OrgID        string `json:"org_id"`
	ActorType    string `json:"actor_type"`
	ActorID      string `json:"actor_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	RoleID       string `json:"role_id"`
}

type membershipDeleteInput struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`
}

func init() {
	// Register role actions.
	Register(Definition{
		Name:       "role.create",
		Impact:     ImpactHigh,
		Permission: "org.permissions",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleRoleCreate,
	})
	Register(Definition{
		Name:       "role.update",
		Impact:     ImpactHigh,
		Permission: "org.permissions",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleRoleUpdate,
	})

	// Register membership actions.
	Register(Definition{
		Name:       "membership.create",
		Impact:     ImpactHigh,
		Permission: "org.permissions",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleMembershipCreate,
	})
	Register(Definition{
		Name:       "membership.delete",
		Impact:     ImpactHigh,
		Permission: "org.permissions",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleMembershipDelete,
	})

	// Register permission listing action.
	Register(Definition{
		Name:       "role.list",
		Impact:     ImpactLow,
		Permission: "org.read",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleRoleList,
	})
}

func handleRoleCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		OrgID  string   `json:"org_id"`
		Name   string   `json:"name"`
		Grants []string `json:"grants"`
		// GrantsStr accepts a comma/whitespace-separated string (htmx form
		// values arrive stringified); supersedes Grants when set (WU-509).
		GrantsStr string `json:"grants_str"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("role.create: %w", err)
	}
	grants := input.Grants
	if len(grants) == 0 && input.GrantsStr != "" {
		grants = splitGrants(input.GrantsStr)
	}
	grantsJSON, err := json.Marshal(grants)
	if err != nil {
		return nil, fmt.Errorf("role.create: marshal grants: %w", err)
	}
	id := newID()
	_, err = ac.Tx.CreateRole(ctx, sqlc.CreateRoleParams{
		ID:         id,
		OrgID:      input.OrgID,
		Name:       input.Name,
		IsSystem:   0,
		GrantsJson: string(grantsJSON),
	})
	if err != nil {
		return nil, fmt.Errorf("role.create: %w", err)
	}
	return map[string]string{"id": id}, nil
}

func handleRoleUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input struct {
		ID        string   `json:"id"`
		OrgID     string   `json:"org_id"`
		Name      string   `json:"name"`
		Grants    []string `json:"grants"`
		GrantsStr string   `json:"grants_str"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("role.update: %w", err)
	}
	grants := input.Grants
	if len(grants) == 0 && input.GrantsStr != "" {
		grants = splitGrants(input.GrantsStr)
	}
	grantsJSON, err := json.Marshal(grants)
	if err != nil {
		return nil, fmt.Errorf("role.update: marshal grants: %w", err)
	}
	// If role is a system role (is_system=1), copy-on-edit: create an org-owned copy.
	existing, err := ac.Tx.FindRoleByID(ctx, sqlc.FindRoleByIDParams{ID: input.ID, OrgID: input.OrgID})
	if err != nil {
		return nil, fmt.Errorf("role.update: find: %w", err)
	}
	if existing.IsSystem == 1 && existing.OrgID != input.OrgID {
		// Copy system role to org.
		id := newID()
		_, err = ac.Tx.CreateRole(ctx, sqlc.CreateRoleParams{
			ID:         id,
			OrgID:      input.OrgID,
			Name:       input.Name,
			IsSystem:   0,
			GrantsJson: string(grantsJSON),
		})
		if err != nil {
			return nil, fmt.Errorf("role.update: copy-on-edit: %w", err)
		}
		return map[string]string{"id": id}, nil
	}
	_, err = ac.Tx.UpdateRoleGrants(ctx, sqlc.UpdateRoleGrantsParams{
		GrantsJson: string(grantsJSON),
		ID:         input.ID,
		OrgID:      input.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("role.update: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleRoleList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	roles, err := ac.Tx.ListRolesByOrg(ctx, ac.Org)
	if err != nil {
		return nil, fmt.Errorf("role.list: %w", err)
	}
	return roles, nil
}

// splitGrants parses a comma/whitespace-separated grant string into a slice,
// trimming empties. Used by role.create/role.update when the htmx form posts a
// flat text field (WU-509) instead of a JSON array.
func splitGrants(s string) []string {
	var out []string
	for _, g := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '	' }) {
		if g != "" {
			out = append(out, g)
		}
	}
	return out
}

func handleMembershipCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input membershipCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("membership.create: %w", err)
	}
	id := newID()
	_, err := ac.Tx.CreateMembership(ctx, sqlc.CreateMembershipParams{
		ID:           id,
		OrgID:        input.OrgID,
		ActorID:      input.ActorID,
		ActorType:    input.ActorType,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
		RoleID:       sql.NullString{String: input.RoleID, Valid: input.RoleID != ""},
	})
	if err != nil {
		return nil, fmt.Errorf("membership.create: %w", err)
	}
	return map[string]string{"id": id}, nil
}

func handleMembershipDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input membershipDeleteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("membership.delete: %w", err)
	}
	if err := ac.Tx.DeleteMembershipByID(ctx, sqlc.DeleteMembershipByIDParams{
		ID:    input.ID,
		OrgID: input.OrgID,
	}); err != nil {
		return nil, fmt.Errorf("membership.delete: %w", err)
	}
	return nil, nil
}
