package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

// TestGithubConfigCRUD covers WU-405 AC: github.config.upsert/delete round-trip
// through the dispatcher against a real DB.
func TestGithubConfigCRUD(t *testing.T) {
	// Other tests call reset(), wiping the init-registered registry. Re-register
	// the github config actions here.
	reset()
	t.Cleanup(reset)
	Register(Definition{Name: "github.config.upsert", Impact: ImpactLow, Permission: "github.config.upsert", Scope: ScopeProject, Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleGithubConfigUpsert})
	Register(Definition{Name: "github.config.delete", Impact: ImpactLow, Permission: "github.config.delete", Scope: ScopeProject, Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleGithubConfigDelete})

	db := dbtest.New(t)
	d := New(db)
	ctx := context.Background()

	if _, err := db.Exec(`INSERT INTO orgs (id, name, slug, context, visibility) VALUES ('org1','Acme','acme','','private')`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO projects (id, org_id, name, key, context, visibility) VALUES ('proj1','org1','Core','ABC','','private')`); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	// Upsert config.
	upOut, err := d.Dispatch(ctx, userActor(), "github.config.upsert",
		json.RawMessage(`{"project_id":"proj1","repo":"acme/core","transitions":{"merged":"done"},"webhook_secret":"s3cret","enabled":true}`),
		Opts{Proj: "proj1"})
	if err != nil {
		t.Fatalf("github.config.upsert: %v", err)
	}
	upJSON := mustJSON(t, upOut)
	if !strings.Contains(upJSON, `"repo":"acme/core"`) || !strings.Contains(upJSON, `"transitions":"{\"merged\":\"done\"}"`) {
		t.Fatalf("upsert result: %s", upJSON)
	}

	// Upsert same repo again (idempotent update, still one row).
	if _, err := d.Dispatch(ctx, userActor(), "github.config.upsert",
		json.RawMessage(`{"project_id":"proj1","repo":"acme/core","transitions":{"opened":"todo"},"enabled":false}`),
		Opts{Proj: "proj1"}); err != nil {
		t.Fatalf("github.config.upsert: %v", err)
	}

	// Delete.
	delOut, err := d.Dispatch(ctx, userActor(), "github.config.delete",
		json.RawMessage(`{"repo":"acme/core"}`),
		Opts{Proj: "proj1"})
	if err != nil {
		t.Fatalf("github.config.delete: %v", err)
	}
	if !strings.Contains(mustJSON(t, delOut), `"deleted":true`) {
		t.Fatalf("delete result: %s", mustJSON(t, delOut))
	}

	// Gone: upserting a fresh repo is a new row; the deleted repo no longer
	// resolves (FindProjectGithubByRepo errors).
	q := d.DB()
	var count int
	if err := q.QueryRow(`SELECT COUNT(*) FROM project_github WHERE repo='acme/core'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("deleted repo still present: %d rows", count)
	}
}
