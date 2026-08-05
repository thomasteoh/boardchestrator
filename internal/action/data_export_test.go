package action

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// TestUserExportGolden asserts the export structure includes all expected sections.
func TestUserExportGolden(t *testing.T) {
	reset()
	t.Cleanup(reset)

	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:       "user.export",
		Impact:     ImpactLow,
		Permission: "user.export",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleUserExport,
	})

	db := dbtest.New(t)
	seedUser(t, db, "user-export-test-1", "export@test.dev", "Export Test")
	d := New(db)
	ctx := context.Background()

	// Create org via dispatch.
	orgResult, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Export Org","slug":"export-org","visibility":"private"}`),
		Opts{})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := extractID(t, mustJSON(t, orgResult))

	q := sqlc.New(db)
	_, err = q.CreateProject(ctx, sqlc.CreateProjectParams{
		ID:    "proj-export-test",
		OrgID: orgID,
		Name:  "Export Project",
		Key:   "EXP",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = q.CreateTask(ctx, sqlc.CreateTaskParams{
		ID:        "task-1",
		ProjectID: "proj-export-test",
		Title:     "Export task",
		Key:       "EXP-1",
		KeyNum:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = q.CreateComment(ctx, sqlc.CreateCommentParams{
		ID:        "comment-1",
		TaskID:    "task-1",
		ProjectID: "proj-export-test",
		AuthorID:  "user-export-test-1",
		Body:      "export comment",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Run export.
	result, err := d.Dispatch(ctx, Actor{Type: ActorUser, ID: "user-export-test-1"}, "user.export",
		json.RawMessage(`{"user_id":"user-export-test-1"}`),
		Opts{})
	if err != nil {
		t.Fatal(err)
	}

	got, ok := result.(userExportOutput)
	if !ok {
		t.Fatalf("expected userExportOutput, got %T", result)
	}

	if got.User.Email != "export@test.dev" {
		t.Errorf("email = %q, want %q", got.User.Email, "export@test.dev")
	}
	if got.User.Name != "Export Test" {
		t.Errorf("name = %q, want %q", got.User.Name, "Export Test")
	}
	if len(got.Comments) != 1 {
		t.Errorf("comments = %d, want 1", len(got.Comments))
	}
}

// TestUserDeleteScrubsPII asserts deletion scrubs PII and reattributes content.
func TestUserDeleteScrubsPII(t *testing.T) {
	reset()
	t.Cleanup(reset)

	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:       "user.delete",
		Impact:     ImpactHigh,
		Permission: "user.delete",
		Scope:      ScopePlatform,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleUserDelete,
	})

	db := dbtest.New(t)
	seedUser(t, db, "user-delete-test-1", "delete@test.dev", "Delete Test")
	d := New(db)
	ctx := context.Background()

	// Create org.
	orgResult, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Delete Org","slug":"delete-org","visibility":"private"}`),
		Opts{})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := extractID(t, mustJSON(t, orgResult))

	q := sqlc.New(db)
	_, err = q.CreateProject(ctx, sqlc.CreateProjectParams{
		ID:    "proj-delete-test",
		OrgID: orgID,
		Name:  "Delete Project",
		Key:   "DEL",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = q.CreateTask(ctx, sqlc.CreateTaskParams{
		ID:        "task-delete-1",
		ProjectID: "proj-delete-test",
		Title:     "Delete task",
		Key:       "DEL-1",
		KeyNum:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = q.CreateComment(ctx, sqlc.CreateCommentParams{
		ID:        "comment-delete-1",
		TaskID:    "task-delete-1",
		ProjectID: "proj-delete-test",
		AuthorID:  "user-delete-test-1",
		Body:      "will be reattributed",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Run delete.
	_, err = d.Dispatch(ctx, Actor{Type: ActorUser, ID: "admin-user"}, "user.delete",
		json.RawMessage(`{"user_id":"user-delete-test-1"}`),
		Opts{})
	if err != nil {
		t.Fatal(err)
	}

	// Verify user PII scrubbed.
	user, err := q.GetUser(ctx, "user-delete-test-1")
	if err != nil {
		t.Fatal(err)
	}
	if user.Email != "" {
		t.Errorf("email not scrubbed: %q", user.Email)
	}
	if !user.DeletedAt.Valid {
		t.Errorf("deleted_at not set")
	}

	// Verify comment reattributed to former member sentinel.
	comments, err := q.ListUserComments(ctx, "ffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	if len(comments) == 0 {
		t.Errorf("no comments reattributed to former member")
	}
	if len(comments) > 0 && comments[0].Body != "will be reattributed" {
		t.Errorf("comment body changed after reattribution: %q", comments[0].Body)
	}
}

// TestOrgExportGolden asserts org export returns all sections.
func TestOrgExportGolden(t *testing.T) {
	reset()
	t.Cleanup(reset)

	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:       "org.export",
		Impact:     ImpactHigh,
		Permission: "org.export",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleOrgExport,
	})

	db := dbtest.New(t)
	d := New(db)
	ctx := context.Background()

	// Create org.
	orgResult, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Golden Org","slug":"golden-org","visibility":"private"}`),
		Opts{})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := extractID(t, mustJSON(t, orgResult))

	q := sqlc.New(db)
	_, err = q.CreateTeam(ctx, sqlc.CreateTeamParams{
		ID:    "team-golden-1",
		OrgID: orgID,
		Name:  "Golden Team",
		Slug:  "golden-team",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = q.CreateProject(ctx, sqlc.CreateProjectParams{
		ID:    "proj-golden-1",
		OrgID: orgID,
		Name:  "Golden Project",
		Key:   "GOLD",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Run org export.
	result, err := d.Dispatch(ctx, userActor(), "org.export",
		json.RawMessage(`{"org_id":"`+orgID+`"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatal(err)
	}

	got, ok := result.(orgExportOutput)
	if !ok {
		t.Fatalf("expected orgExportOutput, got %T", result)
	}

	if got.Org.Slug != "golden-org" {
		t.Errorf("org slug = %q, want %q", got.Org.Slug, "golden-org")
	}
	if len(got.Teams) != 1 {
		t.Errorf("teams = %d, want 1", len(got.Teams))
	}
	if len(got.Projects) != 1 {
		t.Errorf("projects = %d, want 1", len(got.Projects))
	}
}
