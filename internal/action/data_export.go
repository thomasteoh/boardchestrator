package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// --- Input types ---

type userExportInput struct {
	UserID string `json:"user_id"`
}

type userDeleteInput struct {
	UserID string `json:"user_id"`
}

type orgExportInput struct {
	OrgID string `json:"org_id"`
}

// --- Registration ---

func init() {
	Register(Definition{
		Name:       "user.export",
		Impact:     ImpactLow,
		Permission: "user.export",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleUserExport,
	})
	Register(Definition{
		Name:       "user.delete",
		Impact:     ImpactHigh,
		Permission: "user.delete",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleUserDelete,
	})
	Register(Definition{
		Name:       "org.export",
		Impact:     ImpactHigh,
		Permission: "org.export",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleOrgExport,
	})
}

// RegisterDataExportActions ensures init() runs from cmd/bc/serve.go.
func RegisterDataExportActions() {}

// --- Output types ---

type userExportOutput struct {
	User          UserProfile                      `json:"user"`
	Identities    []sqlc.ListUserIdentitiesRow     `json:"identities"`
	Memberships   []sqlc.ListUserMembershipsRow    `json:"memberships"`
	APIKeys       []sqlc.ListUserApiKeysRow        `json:"api_keys"`
	Comments      []sqlc.ListUserCommentsRow       `json:"comments"`
	Activity      []sqlc.ListUserTaskActivityRow   `json:"activity"`
	Assignments   []sqlc.TaskAssignee              `json:"task_assignments"`
	Watchers      []sqlc.TaskWatcher               `json:"task_watchers"`
	Filters       []sqlc.SavedFilter               `json:"saved_filters"`
	Notifications []sqlc.Notification              `json:"notifications"`
	Sessions      []sqlc.Session                   `json:"sessions"`
}

type UserProfile struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
	Theme     string `json:"theme"`
	Timezone  string `json:"timezone"`
	CreatedAt string `json:"created_at"`
	DeletedAt string `json:"deleted_at,omitempty"`
}

// --- Handlers ---

func handleUserExport(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input userExportInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("user.export: %w", err)
	}

	q := sqlc.New(ac.DB)

	user, err := q.GetUser(ctx, input.UserID)
	if err != nil {
		return nil, fmt.Errorf("user.export: get user: %w", err)
	}

	identities, _ := q.ListUserIdentities(ctx, input.UserID)
	memberships, _ := q.ListUserMemberships(ctx, input.UserID)
	apiKeys, _ := q.ListUserApiKeys(ctx, input.UserID)
	comments, _ := q.ListUserComments(ctx, input.UserID)
	activity, _ := q.ListUserTaskActivity(ctx, input.UserID)
	assignments, _ := q.ListUserTaskAssignments(ctx, input.UserID)
	watchers, _ := q.ListUserWatchers(ctx, input.UserID)
	filters, _ := q.ListUserSavedFilters(ctx, input.UserID)
	notifications, _ := q.ListUserNotifications(ctx, input.UserID)
	sessions, _ := q.ListUserSessions(ctx, input.UserID)

	if identities == nil {
		identities = []sqlc.ListUserIdentitiesRow{}
	}
	if memberships == nil {
		memberships = []sqlc.ListUserMembershipsRow{}
	}
	if apiKeys == nil {
		apiKeys = []sqlc.ListUserApiKeysRow{}
	}
	if comments == nil {
		comments = []sqlc.ListUserCommentsRow{}
	}
	if activity == nil {
		activity = []sqlc.ListUserTaskActivityRow{}
	}
	if assignments == nil {
		assignments = []sqlc.TaskAssignee{}
	}
	if watchers == nil {
		watchers = []sqlc.TaskWatcher{}
	}
	if filters == nil {
		filters = []sqlc.SavedFilter{}
	}
	if notifications == nil {
		notifications = []sqlc.Notification{}
	}
	if sessions == nil {
		sessions = []sqlc.Session{}
	}

	profile := UserProfile{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		AvatarURL: user.AvatarUrl,
		Theme:     user.Theme,
		Timezone:  user.Timezone,
		CreatedAt: user.CreatedAt,
	}
	if user.DeletedAt.Valid {
		profile.DeletedAt = user.DeletedAt.String
	}

	return userExportOutput{
		User:          profile,
		Identities:    identities,
		Memberships:   memberships,
		APIKeys:       apiKeys,
		Comments:      comments,
		Activity:      activity,
		Assignments:   assignments,
		Watchers:      watchers,
		Filters:       filters,
		Notifications: notifications,
		Sessions:      sessions,
	}, nil
}

func handleUserDelete(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input userDeleteInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("user.delete: %w", err)
	}

	// Delete all owned data within the dispatch transaction.
	if err := ac.Tx.DeleteUserIdentities(ctx, input.UserID); err != nil {
		return nil, fmt.Errorf("user.delete: identities: %w", err)
	}
	if err := ac.Tx.DeleteUserSessions(ctx, input.UserID); err != nil {
		return nil, fmt.Errorf("user.delete: sessions: %w", err)
	}
	if err := ac.Tx.DeleteUserMemberships(ctx, input.UserID); err != nil {
		return nil, fmt.Errorf("user.delete: memberships: %w", err)
	}
	if err := ac.Tx.DeleteUserApiKeys(ctx, input.UserID); err != nil {
		return nil, fmt.Errorf("user.delete: api keys: %w", err)
	}
	if err := ac.Tx.DeleteUserNotifications(ctx, input.UserID); err != nil {
		return nil, fmt.Errorf("user.delete: notifications: %w", err)
	}

	// Reattribute authored content to "Former member" sentinel.
	actorRef := ac.Actor.ref()
	if err := ac.Tx.ReattributeComments(ctx, sqlc.ReattributeCommentsParams{
		DeletedBy: actorRef,
		AuthorID:  input.UserID,
	}); err != nil {
		return nil, fmt.Errorf("user.delete: comments: %w", err)
	}
	if err := ac.Tx.ReattributeTaskActivity(ctx, sqlc.ReattributeTaskActivityParams{
		DeletedBy: actorRef,
		ActorID:   input.UserID,
	}); err != nil {
		return nil, fmt.Errorf("user.delete: activity: %w", err)
	}

	// Remove task assignments and watchers for the deleted user.
	if err := ac.Tx.ReattributeTaskAssignees(ctx, input.UserID); err != nil {
		return nil, fmt.Errorf("user.delete: assignees: %w", err)
	}
	if err := ac.Tx.ReattributeTaskWatchers(ctx, input.UserID); err != nil {
		return nil, fmt.Errorf("user.delete: watchers: %w", err)
	}

	// Delete saved filters created by user.
	if err := ac.Tx.DeleteUserSavedFilters(ctx, input.UserID); err != nil {
		return nil, fmt.Errorf("user.delete: saved filters: %w", err)
	}

	// Scrub the user record.
	if err := ac.Tx.DeleteUser(ctx, input.UserID); err != nil {
		return nil, fmt.Errorf("user.delete: user record: %w", err)
	}

	return map[string]string{"status": "deleted", "user_id": input.UserID}, nil
}

type orgExportOutput struct {
	Org         sqlc.Org          `json:"org"`
	Teams       []sqlc.Team       `json:"teams"`
	Projects    []sqlc.Project    `json:"projects"`
	Roles       []sqlc.Role       `json:"roles"`
	Memberships []sqlc.Membership `json:"memberships"`
	Secrets     []sqlc.OrgSecret  `json:"secrets"`
	Labels      []sqlc.Label      `json:"labels"`
}

func handleOrgExport(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input orgExportInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("org.export: %w", err)
	}

	q := sqlc.New(ac.DB)

	org, err := q.FindOrgByID(ctx, input.OrgID)
	if err != nil {
		return nil, fmt.Errorf("org.export: get org: %w", err)
	}

	teams, _ := q.ListOrgTeams(ctx, input.OrgID)
	projects, _ := q.ListOrgProjects(ctx, input.OrgID)
	roles, _ := q.ListOrgRoles(ctx, input.OrgID)
	memberships, _ := q.ListOrgMemberships(ctx, input.OrgID)
	secrets, _ := q.ListOrgSecrets2(ctx, input.OrgID)
	labels, _ := q.ListLabelsByOrg(ctx, input.OrgID)

	if teams == nil {
		teams = []sqlc.Team{}
	}
	if projects == nil {
		projects = []sqlc.Project{}
	}
	if roles == nil {
		roles = []sqlc.Role{}
	}
	if memberships == nil {
		memberships = []sqlc.Membership{}
	}
	if secrets == nil {
		secrets = []sqlc.OrgSecret{}
	}
	if labels == nil {
		labels = []sqlc.Label{}
	}

	return orgExportOutput{
		Org:         org,
		Teams:       teams,
		Projects:    projects,
		Roles:       roles,
		Memberships: memberships,
		Secrets:     secrets,
		Labels:      labels,
	}, nil
}
