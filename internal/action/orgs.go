package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// --- Action definitions for org/team/project CRUD ---

// orgCreateInput is the input for org.create.
type orgCreateInput struct {
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	Visibility string `json:"visibility"`
}

// orgUpdateInput is the input for org.update.
type orgUpdateInput struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Context    string `json:"context"`
	Visibility string `json:"visibility"`
}

// teamCreateInput is the input for team.create.
type teamCreateInput struct {
	OrgID      string `json:"org_id"`
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	Visibility string `json:"visibility"`
}

// teamUpdateInput is the input for team.update.
type teamUpdateInput struct {
	ID         string `json:"id"`
	OrgID      string `json:"org_id"`
	Name       string `json:"name"`
	Context    string `json:"context"`
	Visibility string `json:"visibility"`
}

// projectCreateInput is the input for project.create.
type projectCreateInput struct {
	OrgID      string `json:"org_id"`
	TeamID     string `json:"team_id"`
	Name       string `json:"name"`
	Key        string `json:"key"`
	Visibility string `json:"visibility"`
}

// projectUpdateInput is the input for project.update.
type projectUpdateInput struct {
	ID         string `json:"id"`
	OrgID      string `json:"org_id"`
	Name       string `json:"name"`
	Context    string `json:"context"`
	Visibility string `json:"visibility"`
}

// projectArchiveInput is the input for project.archive / unarchive.
type projectArchiveInput struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`
}

var projectKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}$`)

func init() {
	// Register org actions.
	Register(Definition{
		Name:       "org.create",
		Impact:     ImpactHigh,
		Permission: "org.create",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }), // TODO: proper schema
		Handle:     handleOrgCreate,
	})
	Register(Definition{
		Name:       "org.update",
		Impact:     ImpactHigh,
		Permission: "org.update",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleOrgUpdate,
	})

	// Register team actions.
	Register(Definition{
		Name:       "team.create",
		Impact:     ImpactHigh,
		Permission: "team.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTeamCreate,
	})
	Register(Definition{
		Name:       "team.update",
		Impact:     ImpactHigh,
		Permission: "team.update",
		Scope:      ScopeTeam,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleTeamUpdate,
	})

	// Register project actions.
	Register(Definition{
		Name:       "project.create",
		Impact:     ImpactHigh,
		Permission: "project.create",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProjectCreate,
	})
	Register(Definition{
		Name:       "project.update",
		Impact:     ImpactHigh,
		Permission: "project.update",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProjectUpdate,
	})
	Register(Definition{
		Name:       "project.archive",
		Impact:     ImpactHigh,
		Permission: "project.archive",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProjectArchive,
	})
	Register(Definition{
		Name:       "project.unarchive",
		Impact:     ImpactHigh,
		Permission: "project.unarchive",
		Scope:      ScopeProject,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleProjectUnarchive,
	})
}

// RegisterOrgActions is exported so cmd/bc/serve.go can ensure the action package's init() runs.
func RegisterOrgActions() {}

func handleOrgCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input orgCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("org.create: %w", err)
	}
	id := newID()
	_, err := ac.Tx.CreateOrg(ctx, sqlc.CreateOrgParams{
		ID:         id,
		Name:       input.Name,
		Slug:       input.Slug,
		Context:    "",
		Visibility: input.Visibility,
	})
	if err != nil {
		return nil, fmt.Errorf("org.create: %w", err)
	}
	// Seed the org-owner system role (WU-311 kill-switch): the creator becomes
	// an owner holding org.* + agent.* + agent.kill, so they can kill all
	// agents instantly. A new org starts with exactly one owner.
	ownerGrants, _ := json.Marshal([]string{"org.*", "agent.*", "agent.kill", "org.cap.set", "org.read"})
	if _, err := ac.Tx.CreateRole(ctx, sqlc.CreateRoleParams{
		ID:         newID(),
		OrgID:      id,
		Name:       "Owner",
		IsSystem:   1,
		GrantsJson: string(ownerGrants),
	}); err != nil {
		return nil, fmt.Errorf("org.create: seed owner role: %w", err)
	}
	// The creator actor holds the owner membership (actor_type "user").
	ownerRole, err := ac.Tx.FindRoleByName2(ctx, sqlc.FindRoleByName2Params{OrgID: id, Name: "Owner"})
	if err != nil {
		return nil, fmt.Errorf("org.create: find owner role: %w", err)
	}
	if _, err := ac.Tx.CreateMembership(ctx, sqlc.CreateMembershipParams{
		ID:           newID(),
		OrgID:        id,
		ActorID:      ac.Actor.ID,
		ActorType:    "user",
		ResourceType: "org",
		ResourceID:   id,
		RoleID:       sql.NullString{String: ownerRole.ID, Valid: true},
	}); err != nil {
		return nil, fmt.Errorf("org.create: seed owner membership: %w", err)
	}
	return map[string]string{"id": id}, nil
}

func handleOrgUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input orgUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("org.update: %w", err)
	}
	if _, err := ac.Tx.UpdateOrg(ctx, sqlc.UpdateOrgParams{
		Name:       input.Name,
		Context:    input.Context,
		Visibility: input.Visibility,
		ID:         input.ID,
	}); err != nil {
		return nil, fmt.Errorf("org.update: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleTeamCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input teamCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("team.create: %w", err)
	}
	id := newID()
	_, err := ac.Tx.CreateTeam(ctx, sqlc.CreateTeamParams{
		ID:         id,
		OrgID:      input.OrgID,
		Name:       input.Name,
		Slug:       input.Slug,
		Context:    "",
		Visibility: input.Visibility,
	})
	if err != nil {
		return nil, fmt.Errorf("team.create: %w", err)
	}
	return map[string]string{"id": id}, nil
}

func handleTeamUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input teamUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("team.update: %w", err)
	}
	if _, err := ac.Tx.UpdateTeam(ctx, sqlc.UpdateTeamParams{
		Name:       input.Name,
		Context:    input.Context,
		Visibility: input.Visibility,
		ID:         input.ID,
		OrgID:      input.OrgID,
	}); err != nil {
		return nil, fmt.Errorf("team.update: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleProjectCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input projectCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("project.create: %w", err)
	}
	if !projectKeyRe.MatchString(input.Key) {
		return nil, fmt.Errorf("project.create: invalid key %q — must match ^[A-Z][A-Z0-9]{1,9}$", input.Key)
	}
	id := newID()
	_, err := ac.Tx.CreateProject(ctx, sqlc.CreateProjectParams{
		ID:         id,
		OrgID:      input.OrgID,
		TeamID:     sql.NullString{String: input.TeamID, Valid: input.TeamID != ""},
		Name:       input.Name,
		Key:        input.Key,
		Context:    "",
		Visibility: input.Visibility,
	})
	if err != nil {
		return nil, fmt.Errorf("project.create: %w", err)
	}
	return map[string]string{"id": id}, nil
}

func handleProjectUpdate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input projectUpdateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("project.update: %w", err)
	}
	if _, err := ac.Tx.UpdateProject(ctx, sqlc.UpdateProjectParams{
		Name:       input.Name,
		Context:    input.Context,
		Visibility: input.Visibility,
		ID:         input.ID,
		OrgID:      input.OrgID,
	}); err != nil {
		return nil, fmt.Errorf("project.update: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleProjectArchive(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input projectArchiveInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("project.archive: %w", err)
	}
	if err := ac.Tx.ArchiveProject(ctx, sqlc.ArchiveProjectParams{
		ID:    input.ID,
		OrgID: input.OrgID,
	}); err != nil {
		return nil, fmt.Errorf("project.archive: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

func handleProjectUnarchive(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input projectArchiveInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("project.unarchive: %w", err)
	}
	if err := ac.Tx.UnarchiveProject(ctx, sqlc.UnarchiveProjectParams{
		ID:    input.ID,
		OrgID: input.OrgID,
	}); err != nil {
		return nil, fmt.Errorf("project.unarchive: %w", err)
	}
	return map[string]string{"id": input.ID}, nil
}

// DBScopeResolver implements ScopeResolver with DB-backed existence + membership checks.
type DBScopeResolver struct {
	q *sqlc.Queries
}

func NewDBScopeResolver(d *sql.DB) *DBScopeResolver {
	return &DBScopeResolver{q: sqlc.New(d)}
}

func (r *DBScopeResolver) Resolve(ctx context.Context, ac ActionCtx, def Definition) error {
	switch def.Scope {
	case ScopePlatform:
		return nil // no scope to check
	case ScopeOrg:
		if ac.Org == "" {
			return fmt.Errorf("missing org_id for org-scoped action")
		}
		// Verify org exists.
		_, err := r.q.FindOrgByID(ctx, ac.Org)
		if err != nil {
			return fmt.Errorf("org %s not found: %w", ac.Org, err)
		}
		return nil
	case ScopeTeam:
		if ac.Org == "" || ac.Team == "" {
			return fmt.Errorf("missing org_id or team_id for team-scoped action")
		}
		// Verify team exists and belongs to org.
		team, err := r.q.FindTeamByID(ctx, sqlc.FindTeamByIDParams{ID: ac.Team, OrgID: ac.Org})
		if err != nil {
			return fmt.Errorf("team %s not found: %w", ac.Team, err)
		}
		if team.OrgID != ac.Org {
			return fmt.Errorf("team %s does not belong to org %s", ac.Team, ac.Org)
		}
		return nil
	case ScopeProject:
		if ac.Org == "" || ac.Proj == "" {
			return fmt.Errorf("missing org_id or project_id for project-scoped action")
		}
		proj, err := r.q.FindProjectByID(ctx, sqlc.FindProjectByIDParams{ID: ac.Proj, OrgID: ac.Org})
		if err != nil {
			return fmt.Errorf("project %s not found: %w", ac.Proj, err)
		}
		if proj.OrgID != ac.Org {
			return fmt.Errorf("project %s does not belong to org %s", ac.Proj, ac.Org)
		}
		return nil
	default:
		return fmt.Errorf("unknown scope kind %d", def.Scope)
	}
}
