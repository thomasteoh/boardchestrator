package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

func TestBoardColumnCreateAndLookup(t *testing.T) {
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
		Name:   "board.column.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleBoardColCreate,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	// Create an org
	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Org","slug":"org","visibility":"private"}`),
		Opts{Org: ""})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgJSON := mustJSON(t, orgOut)
	if !strings.Contains(orgJSON, `"id"`) {
		t.Fatalf("org result missing id: %s", orgJSON)
	}

	// Create a project
	projOut, err := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+extractID(t, orgJSON)+`","name":"Proj","key":"PROJ","visibility":"private"}`),
		Opts{Org: extractID(t, orgJSON)})
	if err != nil {
		t.Fatalf("project.create: %v", err)
	}
	projJSON := mustJSON(t, projOut)
	if !strings.Contains(projJSON, `"id"`) {
		t.Fatalf("project result missing id: %s", projJSON)
	}

	// Create a board column
	colOut, err := d.Dispatch(ctx, userActor(), "board.column.create",
		json.RawMessage(`{"project_id":"`+extractID(t, projJSON)+`","name":"Todo","color":"#6366f1","wip_limit":5,"status":"backlog"}`),
		Opts{Org: extractID(t, orgJSON)})
	if err != nil {
		t.Fatalf("board.column.create: %v", err)
	}
	colJSON := mustJSON(t, colOut)
	if !strings.Contains(colJSON, `"id"`) {
		t.Fatalf("board column result missing id: %s", colJSON)
	}
}

func TestBoardColumnUpdate(t *testing.T) {
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
		Name:   "board.column.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleBoardColCreate,
	})
	Register(Definition{
		Name:   "board.column.update",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleBoardColUpdate,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgOut, _ := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Org","slug":"org2","visibility":"private"}`), Opts{Org: ""})
	orgID := extractID(t, mustJSON(t, orgOut))
	projOut, _ := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"Proj","key":"PROJ2","visibility":"private"}`), Opts{Org: orgID})
	projID := extractID(t, mustJSON(t, projOut))
	colOut, _ := d.Dispatch(ctx, userActor(), "board.column.create",
		json.RawMessage(`{"project_id":"`+projID+`","name":"Todo","color":"#6366f1","wip_limit":5,"status":"backlog"}`), Opts{Org: orgID})
	colID := extractID(t, mustJSON(t, colOut))

	// Update
	_, err := d.Dispatch(ctx, userActor(), "board.column.update",
		json.RawMessage(`{"id":"`+colID+`","project_id":"`+projID+`","name":"In Progress","color":"#22c55e","wip_limit":3,"status":"active"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("board.column.update: %v", err)
	}
}

func TestBoardColumnDelete(t *testing.T) {
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
		Name:   "board.column.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleBoardColCreate,
	})
	Register(Definition{
		Name:   "board.column.delete",
		Impact: ImpactHigh,
		Scope:  ScopeProject,
		Handle: handleBoardColDelete,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgOut, _ := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Org","slug":"org3","visibility":"private"}`), Opts{Org: ""})
	orgID := extractID(t, mustJSON(t, orgOut))
	projOut, _ := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"Proj","key":"PROJ3","visibility":"private"}`), Opts{Org: orgID})
	projID := extractID(t, mustJSON(t, projOut))
	colOut, _ := d.Dispatch(ctx, userActor(), "board.column.create",
		json.RawMessage(`{"project_id":"`+projID+`","name":"Todo","color":"#6366f1","wip_limit":5,"status":"backlog"}`), Opts{Org: orgID})
	colID := extractID(t, mustJSON(t, colOut))

	// Delete
	_, err := d.Dispatch(ctx, userActor(), "board.column.delete",
		json.RawMessage(`{"id":"`+colID+`","project_id":"`+projID+`"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("board.column.delete: %v", err)
	}
}

func TestBoardColumnReorder(t *testing.T) {
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
		Name:   "board.column.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleBoardColCreate,
	})
	Register(Definition{
		Name:   "board.column.reorder",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleBoardColReorder,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgOut, _ := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Org","slug":"org4","visibility":"private"}`), Opts{Org: ""})
	orgID := extractID(t, mustJSON(t, orgOut))
	projOut, _ := d.Dispatch(ctx, userActor(), "project.create",
		json.RawMessage(`{"org_id":"`+orgID+`","name":"Proj","key":"PROJ4","visibility":"private"}`), Opts{Org: orgID})
	projID := extractID(t, mustJSON(t, projOut))
	col1Out, _ := d.Dispatch(ctx, userActor(), "board.column.create",
		json.RawMessage(`{"project_id":"`+projID+`","name":"Col1","color":"#6366f1","wip_limit":0,"status":"backlog"}`), Opts{Org: orgID})
	col1ID := extractID(t, mustJSON(t, col1Out))
	col2Out, _ := d.Dispatch(ctx, userActor(), "board.column.create",
		json.RawMessage(`{"project_id":"`+projID+`","name":"Col2","color":"#22c55e","wip_limit":0,"status":"active"}`), Opts{Org: orgID})
	_ = extractID(t, mustJSON(t, col2Out))

	// Reorder: move col1 to position 5
	_, err := d.Dispatch(ctx, userActor(), "board.column.reorder",
		json.RawMessage(`{"id":"`+col1ID+`","project_id":"`+projID+`","position":5}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("board.column.reorder: %v", err)
	}
}

// extractID parses the "id" field from a dispatch result JSON string.
func extractID(t *testing.T, jsonStr string) string {
	t.Helper()
	// Find `"id":"<value>"` or `"id":<value>`
	prefix := `"id":"`
	idx := strings.Index(jsonStr, prefix)
	if idx < 0 {
		t.Fatalf("cannot find id in: %s", jsonStr)
	}
	start := idx + len(prefix)
	end := strings.IndexByte(jsonStr[start:], '"')
	if end < 0 {
		t.Fatalf("cannot find closing quote for id in: %s", jsonStr)
	}
	return jsonStr[start : start+end]
}
