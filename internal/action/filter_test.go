package action

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

func TestSavedFilterCreateUpdateDelete(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerBaseActions()
	registerFilterActions()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, projID := createOrgAndProject(t, d, ctx, "FILT1")

	// Create
	out, err := d.Dispatch(ctx, userActor(), "saved_filter.create",
		json.RawMessage(`{"project_id":"`+projID+`","name":"My Filter","query_json":"{\"status\":\"backlog\"}","pinned":true}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("saved_filter.create: %v", err)
	}
	id := extractID(t, mustJSON(t, out))

	// Update
	_, err = d.Dispatch(ctx, userActor(), "saved_filter.update",
		json.RawMessage(`{"id":"`+id+`","project_id":"`+projID+`","name":"Renamed","query_json":"{}","pinned":false}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("saved_filter.update: %v", err)
	}

	// Delete
	_, err = d.Dispatch(ctx, userActor(), "saved_filter.delete",
		json.RawMessage(`{"id":"`+id+`","project_id":"`+projID+`"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("saved_filter.delete: %v", err)
	}
}

func TestTaskBulkAssign(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerBaseActions()
	registerFilterActions()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, projID := createOrgAndProject(t, d, ctx, "BLKA1")

	// Create a real user in the DB via the underlying sql.DB
	q := sqlc.New(d.db)
	if err := q.CreateUser(ctx, sqlc.CreateUserParams{
		ID:    "user_1",
		Email: "user1@test.dev",
		Name:  "User 1",
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create 2 tasks
	t1Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"Task A","status":"backlog"}`),
		Opts{Org: orgID})
	t1ID := extractID(t, mustJSON(t, t1Out))
	t2Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"Task B","status":"backlog"}`),
		Opts{Org: orgID})
	t2ID := extractID(t, mustJSON(t, t2Out))

	// Bulk assign both to a user
	_, err := d.Dispatch(ctx, userActor(), "task.bulk_assign",
		json.RawMessage(`{"project_id":"`+projID+`","task_ids":["`+t1ID+`","`+t2ID+`"],"user_ids":["user_1"]}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("task.bulk_assign: %v", err)
	}
}

func TestTaskBulkMove(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerBaseActions()
	registerFilterActions()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, projID := createOrgAndProject(t, d, ctx, "BLKM1")

	t1Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"Task A","status":"backlog"}`),
		Opts{Org: orgID})
	t1ID := extractID(t, mustJSON(t, t1Out))
	t2Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"Task B","status":"backlog"}`),
		Opts{Org: orgID})
	t2ID := extractID(t, mustJSON(t, t2Out))

	// Bulk move both to in_progress
	_, err := d.Dispatch(ctx, userActor(), "task.bulk_move",
		json.RawMessage(`{"project_id":"`+projID+`","task_ids":["`+t1ID+`","`+t2ID+`"],"to_status":"in_progress"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("task.bulk_move: %v", err)
	}
}

func TestTaskBulkLabel(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerBaseActions()
	registerFilterActions()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, projID := createOrgAndProject(t, d, ctx, "BLKL1")

	t1Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"Task A","status":"backlog"}`),
		Opts{Org: orgID})
	t1ID := extractID(t, mustJSON(t, t1Out))

	// Create a label first
	lblOut, _ := d.Dispatch(ctx, userActor(), "label.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"Bug","color":"red"}`),
		Opts{Org: orgID})
	lblID := extractID(t, mustJSON(t, lblOut))

	// Bulk label
	_, err := d.Dispatch(ctx, userActor(), "task.bulk_label",
		json.RawMessage(`{"project_id":"`+projID+`","task_ids":["`+t1ID+`"],"label_ids":["`+lblID+`"]}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("task.bulk_label: %v", err)
	}
}

// registerFilterActions registers the filter and bulk actions.
func registerFilterActions() {
	Register(Definition{
		Name:   "saved_filter.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleSavedFilterCreate,
	})
	Register(Definition{
		Name:   "saved_filter.update",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleSavedFilterUpdate,
	})
	Register(Definition{
		Name:   "saved_filter.delete",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleSavedFilterDelete,
	})
	Register(Definition{
		Name:   "task.bulk_assign",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTaskBulkAssign,
	})
	Register(Definition{
		Name:   "task.bulk_label",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTaskBulkLabel,
	})
	Register(Definition{
		Name:   "task.bulk_move",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTaskBulkMove,
	})
	Register(Definition{
		Name:   "label.create",
		Impact: ImpactLow,
		Scope:  ScopeOrg,
		Handle: handleLabelCreate,
	})
}
