package action

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

func TestTaskMoveWithinColumn(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerBaseActions()
	Register(Definition{
		Name:   "task.move",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTaskMove,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, projID := createOrgAndProject(t, d, ctx, "MOVE1")

	// Create two tasks
	t1Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"Task A","status":"backlog"}`),
		Opts{Org: orgID})
	t1ID := extractID(t, mustJSON(t, t1Out))
	t2Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"Task B","status":"backlog"}`),
		Opts{Org: orgID})
	_ = extractID(t, mustJSON(t, t2Out))

	// Move t1 to position 100 (after t2)
	_, err := d.Dispatch(ctx, userActor(), "task.move",
		json.RawMessage(`{"id":"`+t1ID+`","project_id":"`+projID+`","to_status":"backlog","sort_order":100}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("task.move: %v", err)
	}
}

func TestTaskMoveBetweenColumns(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerBaseActions()
	Register(Definition{
		Name:   "task.move",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTaskMove,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, projID := createOrgAndProject(t, d, ctx, "MOVE2")

	// Create task in backlog
	t1Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"Task X","status":"backlog"}`),
		Opts{Org: orgID})
	t1ID := extractID(t, mustJSON(t, t1Out))

	// Move to "in_progress"
	out, err := d.Dispatch(ctx, userActor(), "task.move",
		json.RawMessage(`{"id":"`+t1ID+`","project_id":"`+projID+`","to_status":"in_progress","sort_order":1}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("task.move cross-column: %v", err)
	}
	got := mustJSON(t, out)
	if !contains(got, `"status"`) {
		t.Fatalf("result missing status: %s", got)
	}
}

func TestTaskMoveRebalance(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerBaseActions()
	Register(Definition{
		Name:   "task.move",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleTaskMove,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, projID := createOrgAndProject(t, d, ctx, "REBAL")

	// Create 3 tasks in backlog, then reorder via midpoint positions
	t1Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"A","status":"backlog"}`),
		Opts{Org: orgID})
	t1ID := extractID(t, mustJSON(t, t1Out))
	t2Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"B","status":"backlog"}`),
		Opts{Org: orgID})
	_ = extractID(t, mustJSON(t, t2Out))
	t3Out, _ := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"C","status":"backlog"}`),
		Opts{Org: orgID})
	t3ID := extractID(t, mustJSON(t, t3Out))

	// Move t1 between t3 and the end — position 150
	_, err := d.Dispatch(ctx, userActor(), "task.move",
		json.RawMessage(`{"id":"`+t1ID+`","project_id":"`+projID+`","to_status":"backlog","sort_order":150}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("task.move rebalance: %v", err)
	}

	// Move t3 to "in_progress" at position 1
	_, err = d.Dispatch(ctx, userActor(), "task.move",
		json.RawMessage(`{"id":"`+t3ID+`","project_id":"`+projID+`","to_status":"in_progress","sort_order":1}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("task.move cross-column rebalance: %v", err)
	}
}

// registerBaseActions registers org.create and project.create for test setup.
func registerBaseActions() {
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
}

// createOrgAndProject creates an org+project and returns their IDs.
func createOrgAndProject(t *testing.T, d *Dispatcher, ctx context.Context, slug string) (string, string) {
	t.Helper()
	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Org","slug":"`+slug+`","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := extractID(t, mustJSON(t, orgOut))

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"Proj","key":"`+slug+`","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projID := extractID(t, mustJSON(t, projOut))
	return orgID, projID
}
