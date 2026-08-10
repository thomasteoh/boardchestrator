package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
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

	// Seed an agent so the column trigger_agent_id FK is satisfied.
	q := sqlc.New(d.DB())
	if _, err := q.CreateProvider(ctx, sqlc.CreateProviderParams{ID: "prov2", Kind: "openai-compatible", Name: "T", BaseUrl: "https://t/v1", KeyEnc: nil, ModelsJson: `["gpt-4o"]`}); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if _, err := q.CreateRole(ctx, sqlc.CreateRoleParams{ID: "role2", OrgID: orgID, Name: "Editor", IsSystem: 0, GrantsJson: `["task.list"]`}); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if _, err := q.CreateAgent(ctx, sqlc.CreateAgentParams{
		ID: "agt2", OrgID: sql.NullString{String: orgID, Valid: true},
		Name: "robo2", ProviderID: "prov2", Model: "gpt-4o", Context: "x",
		RoleID: sql.NullString{String: "role2", Valid: true},
		RetryMax: 3, BackoffSecs: 30, RunsPerHour: 20, TokenBudget: 50000,
		ApprovalPolicyJson: `{}`, Active: 1,
	}); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	colOut, _ := d.Dispatch(ctx, userActor(), "board.column.create",
		json.RawMessage(`{"project_id":"`+projID+`","name":"Todo","color":"#6366f1","wip_limit":5,"status":"backlog","trigger_agent_id":"agt2","trigger_prompt":"Review {title}"}`), Opts{Org: orgID})
	colID := extractID(t, mustJSON(t, colOut))

	// Update
	_, err := d.Dispatch(ctx, userActor(), "board.column.update",
		json.RawMessage(`{"id":"`+colID+`","project_id":"`+projID+`","name":"In Progress","color":"#22c55e","wip_limit":3,"status":"active","trigger_agent_id":"agt2","trigger_prompt":"Triage {title} ({key})"}`),
		Opts{Org: orgID})
	if err != nil {
		t.Fatalf("board.column.update: %v", err)
	}

	// Verify the trigger fields persisted (WU-307 column trigger config).
	col, err := sqlc.New(d.DB()).FindBoardColumn(ctx, sqlc.FindBoardColumnParams{ID: colID, ProjectID: projID})
	if err != nil {
		t.Fatalf("find column: %v", err)
	}
	if !col.TriggerAgentID.Valid || col.TriggerAgentID.String != "agt2" || col.TriggerPrompt != "Triage {title} ({key})" {
		t.Fatalf("trigger config not persisted: agent=%v prompt=%q", col.TriggerAgentID, col.TriggerPrompt)
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
	// Find `"id":"<value>"`, `"ID":"<value>"`, or `"id":<value>`
	var prefix string
	prefix = `"id":"`
	idx := strings.Index(jsonStr, prefix)
	if idx < 0 {
		prefix = `"ID":"`
		idx = strings.Index(jsonStr, prefix)
	}
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
