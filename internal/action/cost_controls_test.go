package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// usagePermChecker mirrors the seeded grants: usage.read is covered by Org
// Owner ("*") only — Team Admin and Member grants exclude it (WU-505 AC:
// org owner only by default).
type usagePermChecker struct{ owner bool }

func (c usagePermChecker) Allow(ctx context.Context, ac ActionCtx, def Definition) (bool, error) {
	if def.Permission != "usage.read" {
		return false, nil
	}
	return c.owner, nil
}

// seedUsageFixture creates an org with a provider, agent, project, pricing, a
// finished run (2 prompt + 3 completion tokens) with one run_steps row, and an
// org-scoped run with no project. Returns the org id.
func seedUsageFixture(t *testing.T, db sqlc.DBTX) string {
	t.Helper()
	ctx := context.Background()
	oid := "org000000000000000000000000001"
	must(t, db, ctx, `INSERT INTO orgs (id, name, slug, context, visibility) VALUES (?, 'O', 'o', '', 'private')`, oid)
	must(t, db, ctx, `INSERT INTO providers (id, kind, name) VALUES ('prov1', 'openai-compatible', 'P')`)
	must(t, db, ctx, `INSERT INTO agents (id, org_id, name, provider_id, model) VALUES ('ag1', ?, 'Agent One', 'prov1', 'm1')`, oid)
	must(t, db, ctx, `INSERT INTO model_pricing (id, provider_id, model, input_per_mtok, output_per_mtok) VALUES ('mp1', 'prov1', 'm1', 1.0, 2.0)`)
	must(t, db, ctx, `INSERT INTO projects (id, org_id, name, key, context, visibility) VALUES ('proj1', ?, 'Project One', 'p', '', 'private')`, oid)
	// Finished project run: 2000 prompt + 3000 completion tokens, one step.
	must(t, db, ctx, `INSERT INTO runs (id, org_id, agent_id, trigger, project_id, status, prompt_tokens, completion_tokens, created_at, finished_at)
		VALUES ('run1', ?, 'ag1', 'manual', 'proj1', 'finished', 2000, 3000, '2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z')`, oid)
	must(t, db, ctx, `INSERT INTO run_steps (id, run_id, seq, kind, tokens) VALUES ('rs1', 'run1', 1, 'model', 5000)`)
	// Finished org-scoped run (no project): 1000 prompt, 1000 completion.
	must(t, db, ctx, `INSERT INTO runs (id, org_id, agent_id, trigger, status, prompt_tokens, completion_tokens, created_at, finished_at)
		VALUES ('run2', ?, 'ag1', 'column', 'finished', 1000, 1000, '2026-01-03T00:00:00.000Z', '2026-01-04T00:00:00.000Z')`, oid)
	must(t, db, ctx, `INSERT INTO run_steps (id, run_id, seq, kind, tokens) VALUES ('rs2', 'run2', 1, 'model', 2000)`)
	return oid
}

func TestUsageReadAggregationGolden(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:       "usage.read",
		Impact:     ImpactRead,
		Permission: "usage.read",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleUsageRead,
	})

	db := dbtest.New(t)
	oid := seedUsageFixture(t, db)
	d := New(db, WithPermissionChecker(usagePermChecker{owner: true}))
	ctx := context.Background()

	raw, err := d.Dispatch(ctx, userActor(), "usage.read",
		json.RawMessage(`{"from":"2026-01-01T00:00:00.000Z","to":"2026-02-01T00:00:00.000Z"}`),
		Opts{Org: oid})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	out := raw.(map[string]any)
	// Totals: cost = 2000/1e6*1 + 3000/1e6*2 + 1000/1e6*1 + 1000/1e6*2
	//       = 0.002 + 0.006 + 0.001 + 0.002 = 0.011
	// tokens = 5000 + 2000 = 7000; runs = 2; actions = 2 (one step each).
	if got := out["total_usd"].(float64); got != 0.011 {
		t.Errorf("total_usd = %v, want 0.011", got)
	}
	if got := out["total_tokens"].(int64); got != 7000 {
		t.Errorf("total_tokens = %v, want 7000", got)
	}
	if got := out["runs"].(int64); got != 2 {
		t.Errorf("runs = %v, want 2", got)
	}
	if got := out["actions"].(int64); got != 2 {
		t.Errorf("actions = %v, want 2", got)
	}

	// by_agent: one agent, 2 runs, 7000 tokens, actions 2, cost 0.011.
	ba := out["by_agent"].([]sqlc.AgentUsageInWindowRow)
	if len(ba) != 1 {
		t.Fatalf("by_agent len = %d, want 1", len(ba))
	}
	if ba[0].Runs != 2 || ba[0].Tokens != 7000 || ba[0].Actions != 2 {
		t.Errorf("agent row = %+v", ba[0])
	}

	// by_project: proj1 (1 run, 5000 tokens, cost 0.008) + "" (org-scoped run).
	bp := out["by_project"].([]sqlc.ProjectUsageInWindowRow)
	if len(bp) != 2 {
		t.Fatalf("by_project len = %d, want 2", len(bp))
	}
	if bp[0].ProjectID != "proj1" || bp[0].Runs != 1 || bp[0].Tokens != 5000 || bp[0].Actions != 1 {
		t.Errorf("proj1 row = %+v", bp[0])
	}
	if bp[1].ProjectID != "" || bp[1].Runs != 1 || bp[1].Tokens != 2000 || bp[1].Actions != 1 {
		t.Errorf("org-scoped row = %+v", bp[1])
	}

	// Drill-down filtered by agent returns both runs.
	raw2, err := d.Dispatch(ctx, userActor(), "usage.read",
		json.RawMessage(`{"from":"2026-01-01T00:00:00.000Z","to":"2026-02-01T00:00:00.000Z","agent_id":"ag1","limit":10}`),
		Opts{Org: oid})
	if err != nil {
		t.Fatalf("dispatch runs: %v", err)
	}
	rl := raw2.(map[string]any)["runs_list"].([]sqlc.Run)
	if len(rl) != 2 {
		t.Fatalf("runs_list len = %d, want 2", len(rl))
	}

	// CSV mode returns RFC 4180 headers.
	raw3, err := d.Dispatch(ctx, userActor(), "usage.read",
		json.RawMessage(`{"from":"2026-01-01T00:00:00.000Z","to":"2026-02-01T00:00:00.000Z","csv":true}`),
		Opts{Org: oid})
	if err != nil {
		t.Fatalf("dispatch csv: %v", err)
	}
	agents := raw3.(map[string]any)["csv_agents"].(string)
	if !strings.HasPrefix(agents, "agent_id,agent_name,runs,tokens,cost_usd,actions\n") {
		t.Errorf("csv_agents missing header: %q", agents)
	}
	if !strings.Contains(agents, "Agent One,2,7000,0.01,2") {
		t.Errorf("csv_agents missing row: %q", agents)
	}
}

// TestUsageReadOwnerOnly asserts usage.read is denied for a non-owner (the
// seeded Member grant excludes usage.read) and allowed for an owner (WU-505 AC).
func TestUsageReadOwnerOnly(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:       "usage.read",
		Impact:     ImpactRead,
		Permission: "usage.read",
		Scope:      ScopeOrg,
		Input:      FuncSchema(func(raw json.RawMessage) error { return nil }),
		Handle:     handleUsageRead,
	})
	db := dbtest.New(t)
	oid := seedUsageFixture(t, db)

	// Owner: allowed.
	owner := New(db, WithPermissionChecker(usagePermChecker{owner: true}))
	if _, err := owner.Dispatch(context.Background(), userActor(), "usage.read",
		json.RawMessage(`{"from":"2026-01-01T00:00:00.000Z","to":"2026-02-01T00:00:00.000Z"}`), Opts{Org: oid}); err != nil {
		t.Fatalf("owner denied: %v", err)
	}
	// Member: denied (no usage.read grant).
	member := New(db, WithPermissionChecker(usagePermChecker{owner: false}))
	_, err := member.Dispatch(context.Background(), userActor(), "usage.read",
		json.RawMessage(`{"from":"2026-01-01T00:00:00.000Z","to":"2026-02-01T00:00:00.000Z"}`), Opts{Org: oid})
	if err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("member not denied: %v", err)
	}
}

func must(t *testing.T, db sqlc.DBTX, ctx context.Context, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, q, args...); err != nil {
		t.Fatalf("seed %q: %v", q, err)
	}
}
