package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

func TestSprintCreateAndLookup(t *testing.T) {
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
		Name:   "sprint.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Input:  FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: handleSprintCreate,
	})
	Register(Definition{
		Name:   "sprint.update",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Input:  FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: handleSprintUpdate,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"TestCo","slug":"testco","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgJSON := mustJSON(t, orgOut)
	orgID := extractID(t, orgJSON)

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"SprintProj","key":"SP","visibility":"private"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projJSON := mustJSON(t, projOut)
	projID := extractID(t, projJSON)

	// Create a sprint
	sprintOut, err := d.Dispatch(ctx, userActor(), "sprint.create",
		json.RawMessage(`{"project_id":"`+projID+`","name":"S1","starts_on":"2026-01-01","ends_on":"2026-01-14"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("sprint.create: %v", err)
	}
	sprintJSON := mustJSON(t, sprintOut)
	if !strings.Contains(sprintJSON, `"ID"`) {
		t.Fatal("sprint result missing ID")
	}
	sprintID := extractID(t, sprintJSON)

	// Update sprint name
	updatedOut, err := d.Dispatch(ctx, userActor(), "sprint.update",
		json.RawMessage(`{"id":"`+sprintID+`","project_id":"`+projID+`","name":"Sprint 1"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("sprint.update: %v", err)
	}
	updatedJSON := mustJSON(t, updatedOut)
	if !strings.Contains(updatedJSON, `"Sprint 1"`) {
		t.Fatalf("sprint.update name not updated: %s", updatedJSON)
	}
}

func TestSprintCloseMovesOpenTasks(t *testing.T) {
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
		Name:   "sprint.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Input:  FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: handleSprintCreate,
	})
	Register(Definition{
		Name:   "sprint.close",
		Impact: ImpactHigh,
		Scope:  ScopeProject,
		Input:  FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: handleSprintClose,
	})
	Register(Definition{
		Name:   "task.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Input:  FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: handleTaskCreate,
	})
	Register(Definition{
		Name:   "sprint.add_task",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Input:  FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: handleSprintAddTask,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O","slug":"o","visibility":"private"}`), Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := extractID(t, mustJSON(t, orgOut))

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P","key":"PR","visibility":"private"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projID := extractID(t, mustJSON(t, projOut))

	sOut, err := d.Dispatch(ctx, userActor(), "sprint.create",
		json.RawMessage(`{"project_id":"`+projID+`","name":"S1","starts_on":"2026-01-01","ends_on":"2026-01-14"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("sprint.create: %v", err)
	}
	sID := extractID(t, mustJSON(t, sOut))

	t1Out, err := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"task1"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("task.create: %v", err)
	}
	t1ID := extractID(t, mustJSON(t, t1Out))
	t2Out, err := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"task2"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("task.create: %v", err)
	}
	t2ID := extractID(t, mustJSON(t, t2Out))

	_, err = d.Dispatch(ctx, userActor(), "sprint.add_task",
		json.RawMessage(`{"id":"`+sID+`","project_id":"`+projID+`","task_id":"`+t1ID+`"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("sprint.add_task: %v", err)
	}
	_, err = d.Dispatch(ctx, userActor(), "sprint.add_task",
		json.RawMessage(`{"id":"`+sID+`","project_id":"`+projID+`","task_id":"`+t2ID+`"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("sprint.add_task (2): %v", err)
	}

	// Close sprint
	resultOut, err := d.Dispatch(ctx, userActor(), "sprint.close",
		json.RawMessage(`{"id":"`+sID+`","project_id":"`+projID+`"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("sprint.close: %v", err)
	}
	resultJSON := mustJSON(t, resultOut)
	if !strings.Contains(resultJSON, `"moved"`) {
		t.Errorf("sprint.close result missing moved count: %s", resultJSON)
	}
}

func TestSprintAddRemoveTask(t *testing.T) {
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
		Name:   "sprint.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Input:  FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: handleSprintCreate,
	})
	Register(Definition{
		Name:   "sprint.add_task",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Input:  FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: handleSprintAddTask,
	})
	Register(Definition{
		Name:   "sprint.remove_task",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Input:  FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: handleSprintRemoveTask,
	})
	Register(Definition{
		Name:   "task.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Input:  FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle: handleTaskCreate,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"O2","slug":"o2","visibility":"private"}`), Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := extractID(t, mustJSON(t, orgOut))

	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"P2","key":"P2","visibility":"private"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projID := extractID(t, mustJSON(t, projOut))

	sOut, err := d.Dispatch(ctx, userActor(), "sprint.create",
		json.RawMessage(`{"project_id":"`+projID+`","name":"S1","starts_on":"2026-01-01","ends_on":"2026-01-14"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("sprint.create: %v", err)
	}
	sID := extractID(t, mustJSON(t, sOut))

	tOut, err := d.Dispatch(ctx, userActor(), "task.create",
		json.RawMessage(`{"project_id":"`+projID+`","title":"t"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("task.create: %v", err)
	}
	tID := extractID(t, mustJSON(t, tOut))

	// Add to sprint
	_, err = d.Dispatch(ctx, userActor(), "sprint.add_task",
		json.RawMessage(`{"id":"`+sID+`","project_id":"`+projID+`","task_id":"`+tID+`"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("sprint.add_task: %v", err)
	}

	// Remove from sprint
	_, err = d.Dispatch(ctx, userActor(), "sprint.remove_task",
		json.RawMessage(`{"id":"`+sID+`","project_id":"`+projID+`","task_id":"`+tID+`"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("sprint.remove_task: %v", err)
	}
}
