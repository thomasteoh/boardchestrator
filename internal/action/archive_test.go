package action

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

func TestTaskArchiveUnarchive(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:   "project.create",
		Impact: ImpactHigh,
		Scope:  ScopeOrg,
		Handle: handleProjectCreate,
	})
	Register(Definition{
		Name:   "task.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTaskCreate,
	})
	Register(Definition{
		Name:   "task.archive",
		Impact: ImpactHigh,
		Scope:  ScopeProject,
		Handle: handleTaskArchive,
	})
	Register(Definition{
		Name:   "task.unarchive",
		Impact: ImpactHigh,
		Scope:  ScopeProject,
		Handle: handleTaskUnarchive,
	})

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O","slug":"o","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := mustParseID(t, orgOut)

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P","key":"PROJ","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projID := mustParseID(t, projOut)

	// Create a task.
	taskIn := map[string]any{
		"project_id": projID,
		"title":      "Task to archive",
		"status":     "backlog",
	}
	raw, _ := json.Marshal(taskIn)
	taskOut, err := d.Dispatch(ctx, userActor(), "task.create", raw, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("task.create: %v", err)
	}
	taskID := mustParseID(t, taskOut)

	// Archive.
	archIn := map[string]any{"id": taskID, "project_id": projID}
	raw3, _ := json.Marshal(archIn)
	_, err = d.Dispatch(ctx, userActor(), "task.archive", raw3, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("task.archive: %v", err)
	}

	// Unarchive.
	unarchIn := map[string]any{"id": taskID, "project_id": projID}
	raw4, _ := json.Marshal(unarchIn)
	_, err = d.Dispatch(ctx, userActor(), "task.unarchive", raw4, Opts{Org: orgID, Proj: projID})
	if err != nil {
		t.Fatalf("task.unarchive: %v", err)
	}
}
