package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// killPerm is a test PermissionChecker that only allows the org owner (u1)
// for agent.kill-all — avoids the action↔perm import cycle.
type killPerm struct {
	allowedID string
}

func (k killPerm) Allow(ctx context.Context, ac ActionCtx, def Definition) (bool, error) {
	if def.Permission == "agent.kill" && ac.Actor.ID != k.allowedID {
		return false, nil
	}
	return true, nil
}

// TestKillSwitchOwner covers WU-311 AC: the org owner (creator, holding the
// seeded Owner role with agent.kill) can disable every agent in the org
// instantly via agent.kill-all; a non-owner without the grant is denied.
func TestKillSwitchOwner(t *testing.T) {
	reset()
	t.Cleanup(reset)
	db := dbtest.New(t)
	ctx := context.Background()
	d := New(db, WithPermissionChecker(killPerm{allowedID: "u1"}))
	// agent.kill-all + org.create are registered by init(); reset() clears the
	// registry, so re-register what this test needs.
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:       "agent.kill-all",
		Impact:     ImpactHigh,
		Permission: "agent.kill",
		Scope:      ScopeOrg,
		Handle:     handleAgentKillAll,
	})
	if _, ok := Lookup("agent.kill-all"); !ok {
		t.Fatalf("agent.kill-all not registered")
	}

	// Create org as u1 → u1 becomes the seeded Owner (handleOrgCreate).
	out, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Acme","slug":"acme","visibility":"private"}`), Opts{})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := killOrgID(t, out)

	// Seed two agents in the org (active=1).
	q := sqlc.New(db)
	mkAgent(t, q, "agtA", orgID)
	mkAgent(t, q, "agtB", orgID)

	// Owner (u1) kills all agents.
	if _, err := d.Dispatch(ctx, userActor(), "agent.kill-all", json.RawMessage(`{}`), Opts{Org: orgID}); err != nil {
		t.Fatalf("owner kill-all: %v", err)
	}
	agents, err := q.ListAgentsByOrg(ctx, sql.NullString{String: orgID, Valid: true})
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	for _, a := range agents {
		if a.Active == 1 {
			t.Fatalf("agent %s still active after kill-all", a.ID)
		}
	}
}

// TestKillSwitchNonOwner covers WU-311: a member without agent.kill is denied.
func TestKillSwitchNonOwner(t *testing.T) {
	reset()
	t.Cleanup(reset)
	db := dbtest.New(t)
	ctx := context.Background()
	d := New(db, WithPermissionChecker(killPerm{allowedID: "u1"}))

	// Re-register after reset().
	Register(Definition{
		Name:   "org.create",
		Impact: ImpactHigh,
		Scope:  ScopePlatform,
		Handle: handleOrgCreate,
	})
	Register(Definition{
		Name:       "agent.kill-all",
		Impact:     ImpactHigh,
		Permission: "agent.kill",
		Scope:      ScopeOrg,
		Handle:     handleAgentKillAll,
	})

	// Create org as owner u1.
	out, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"Acme","slug":"acme2","visibility":"private"}`), Opts{})
	if err != nil {
		t.Fatalf("org.create: %v", err)
	}
	orgID := killOrgID(t, out)

	// u2 (not owner) is denied agent.kill-all by the permission stub.
	actor2 := Actor{Type: ActorUser, ID: "u2", IP: "203.0.113.6"}
	if _, err := d.Dispatch(ctx, actor2, "agent.kill-all", json.RawMessage(`{}`), Opts{Org: orgID}); err == nil {
		t.Fatalf("expected non-owner kill-all to be denied")
	}
}

// mkAgent seeds an active agent in an org for kill-switch tests.
func mkAgent(t *testing.T, q *sqlc.Queries, id, orgID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := q.CreateProvider(ctx, sqlc.CreateProviderParams{
		ID: "prov" + id, Kind: "openai-compatible", Name: "Test", BaseUrl: "https://test/v1",
		KeyEnc: nil, ModelsJson: `["gpt-4o"]`,
	}); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if _, err := q.CreateAgent(ctx, sqlc.CreateAgentParams{
		ID: id, OrgID: sql.NullString{String: orgID, Valid: true},
		Name: "a" + id, ProviderID: "prov" + id, Model: "gpt-4o",
		Context: "ctx", RoleID: sql.NullString{}, RetryMax: 3, BackoffSecs: 30,
		RunsPerHour: 20, TokenBudget: 50000,
		ApprovalPolicyJson: `{"low":"auto","read":"auto","high":"require"}`,
		Active:             1,
	}); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
}

// killOrgID pulls the "id" field out of a JSON handler result.
func killOrgID(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return m["id"]
}
