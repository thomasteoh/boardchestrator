package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// registerAgentFixtures registers the actions agents_test relies on. Each
// action test file owns its registry via reset()+t.Cleanup(reset) — relying on
// the package init() registry leaks across tests and breaks when another test's
// cleanup wipes it.
func registerAgentFixtures() {
	Register(Definition{Name: "org.create", Impact: ImpactHigh, Scope: ScopePlatform, Handle: handleOrgCreate})
	Register(Definition{Name: "provider.create", Impact: ImpactHigh, Scope: ScopePlatform, Handle: handleProviderCreate})
	Register(Definition{Name: "agent.create", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "agent.create", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentCreate})
	Register(Definition{Name: "agent.update", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "agent.update", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentUpdate})
	Register(Definition{Name: "agent.delete", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "agent.delete", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentDelete})
	Register(Definition{Name: "agent.list", Impact: ImpactRead, Scope: ScopeOrg, Permission: "agent.list", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentList})
	Register(Definition{Name: "agent.list-templates", Impact: ImpactRead, Scope: ScopePlatform, Permission: "agent.list-templates", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentListTemplates})
	Register(Definition{Name: "agent.skill-attach", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "agent.update", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentSkillAttach})
	Register(Definition{Name: "agent.skill-detach", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "agent.update", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentSkillDetach})
	Register(Definition{Name: "agent.list-skills", Impact: ImpactRead, Scope: ScopeOrg, Permission: "agent.list", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentListSkills})
}

// seedOrgProvider creates an org and an openai-compatible provider, returning
// their IDs. Requires the org.create / provider.create actions to be registered.
func seedOrgProvider(t *testing.T, d *Dispatcher, name string) (orgID, providerID string) {
	t.Helper()
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"`+name+`","slug":"`+name+`","visibility":"private"}`), Opts{Org: ""})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	orgID = mustJSON(t, orgOut)
	orgID = extractID(t, orgID)

	provOut, err := d.Dispatch(ctx, userActor(), "provider.create",
		json.RawMessage(`{"kind":"openai-compatible","name":"Test Provider","base_url":"https://test.example.com/v1","models":["gpt-4o"]}`), Opts{})
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	providerID = extractID(t, mustJSON(t, provOut))
	return orgID, providerID
}

// seedSkill inserts a skills row directly (the skills hub CRUD arrives in
// WU-304; tests need a real row for the agent_skills FK).
func seedSkill(t *testing.T, d *Dispatcher, id, orgID string) {
	t.Helper()
	_, err := d.DB().Exec(`
		INSERT INTO skills (id, org_id, name, version)
		VALUES (?, ?, ?, 1)`, id, sql.NullString{String: orgID, Valid: orgID != ""}, id)
	if err != nil {
		t.Fatalf("seed skill %s: %v", id, err)
	}
}

func TestAgentCreateAndList(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerAgentFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, providerID := seedOrgProvider(t, d, "test-org")

	// Create an agent
	input := map[string]any{"org_id": orgID, "name": "test-agent", "provider_id": providerID, "model": "gpt-4o"}
	raw, _ := json.Marshal(input)
	result, err := d.Dispatch(ctx, userActor(), "agent.create", raw, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("agent.create: %v", err)
	}
	id := extractID(t, mustJSON(t, result))
	if id == "" {
		t.Fatal("expected non-empty agent id")
	}

	// List agents by org
	listInput := map[string]string{"org_id": orgID}
	rawL, _ := json.Marshal(listInput)
	listResult, err := d.Dispatch(ctx, userActor(), "agent.list", rawL, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("agent.list: %v", err)
	}
	agents := listResult.([]sqlc.Agent)
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if agents[0].Name != "test-agent" {
		t.Fatalf("expected name test-agent, got %s", agents[0].Name)
	}

	// Delete agent within the same org
	deleteInput := map[string]string{"id": id, "org_id": orgID}
	rawD, _ := json.Marshal(deleteInput)
	if _, err = d.Dispatch(ctx, userActor(), "agent.delete", rawD, Opts{Org: orgID}); err != nil {
		t.Fatalf("agent.delete: %v", err)
	}
}

func TestAgentDuplicateNameRejected(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerAgentFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, providerID := seedOrgProvider(t, d, "dup-org")

	input := map[string]any{"org_id": orgID, "name": "dup-agent", "provider_id": providerID, "model": "gpt-4o"}
	raw, _ := json.Marshal(input)
	if _, err := d.Dispatch(ctx, userActor(), "agent.create", raw, Opts{Org: orgID}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := d.Dispatch(ctx, userActor(), "agent.create", raw, Opts{Org: orgID}); err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestAgentListTemplates(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerAgentFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, providerID := seedOrgProvider(t, d, "tmpl-org")

	// Create a platform template (org_id empty = platform)
	tmpl := map[string]any{"org_id": "", "name": "template-agent", "provider_id": providerID, "model": "gpt-4o"}
	rawT, _ := json.Marshal(tmpl)
	if _, err := d.Dispatch(ctx, userActor(), "agent.create", rawT, Opts{Org: ""}); err != nil {
		t.Fatalf("create template: %v", err)
	}

	// Create an org agent
	orgAg := map[string]any{"org_id": orgID, "name": "org-agent", "provider_id": providerID, "model": "claude-3"}
	rawO, _ := json.Marshal(orgAg)
	if _, err := d.Dispatch(ctx, userActor(), "agent.create", rawO, Opts{Org: orgID}); err != nil {
		t.Fatalf("create org agent: %v", err)
	}

	// List templates should only return platform agents
	result, err := d.Dispatch(ctx, userActor(), "agent.list-templates", json.RawMessage("{}"), Opts{Org: ""})
	if err != nil {
		t.Fatalf("agent.list-templates: %v", err)
	}
	templates := result.([]sqlc.Agent)
	if len(templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(templates))
	}
	if templates[0].Name != "template-agent" {
		t.Fatalf("expected template-agent, got %s", templates[0].Name)
	}
}

// TestAgentDeleteCrossOrgRejected — deleting an agent in org B by its id must
// not affect org A's agent (DeleteAgent is scoped by id AND org_id).
func TestAgentDeleteCrossOrgRejected(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerAgentFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgA, provA := seedOrgProvider(t, d, "org-a")
	orgB, _ := seedOrgProvider(t, d, "org-b")

	// Create an agent in org A
	createA := map[string]any{"org_id": orgA, "name": "agent-a", "provider_id": provA, "model": "gpt-4o"}
	rawA, _ := json.Marshal(createA)
	outA, err := d.Dispatch(ctx, userActor(), "agent.create", rawA, Opts{Org: orgA})
	if err != nil {
		t.Fatalf("create agent-a: %v", err)
	}
	agentAID := extractID(t, mustJSON(t, outA))

	// Delete it with org B's id — must be a no-op (no error, agent survives)
	del := map[string]string{"id": agentAID, "org_id": orgB}
	rawD, _ := json.Marshal(del)
	if _, err := d.Dispatch(ctx, userActor(), "agent.delete", rawD, Opts{Org: orgB}); err != nil {
		t.Fatalf("agent.delete cross-org should not error, got: %v", err)
	}

	// Agent A still present
	listA := map[string]string{"org_id": orgA}
	rawL, _ := json.Marshal(listA)
	listRes, err := d.Dispatch(ctx, userActor(), "agent.list", rawL, Opts{Org: orgA})
	if err != nil {
		t.Fatalf("agent.list: %v", err)
	}
	if agents := listRes.([]sqlc.Agent); len(agents) != 1 {
		t.Fatalf("cross-org delete removed org A agent: got %d agents", len(agents))
	}
}

// TestAgentUpdateCrossOrgRejected — updating org A's agent with org B's id must
// not mutate org A's agent (UpdateAgent is scoped by id AND org_id).
func TestAgentUpdateCrossOrgRejected(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerAgentFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgA, provA := seedOrgProvider(t, d, "org-a")
	orgB, _ := seedOrgProvider(t, d, "org-b")

	createA := map[string]any{"org_id": orgA, "name": "agent-a", "provider_id": provA, "model": "gpt-4o"}
	rawA, _ := json.Marshal(createA)
	outA, err := d.Dispatch(ctx, userActor(), "agent.create", rawA, Opts{Org: orgA})
	if err != nil {
		t.Fatalf("create agent-a: %v", err)
	}
	agentAID := extractID(t, mustJSON(t, outA))

	// Update with org B's id — must not touch agent A
	upd := map[string]any{"id": agentAID, "org_id": orgB, "name": "hijacked", "active": true}
	rawU, _ := json.Marshal(upd)
	if _, err := d.Dispatch(ctx, userActor(), "agent.update", rawU, Opts{Org: orgB}); err != nil {
		t.Fatalf("agent.update cross-org should not error, got: %v", err)
	}

	// Verify agent A name unchanged
	listA := map[string]string{"org_id": orgA}
	rawL, _ := json.Marshal(listA)
	listRes, err := d.Dispatch(ctx, userActor(), "agent.list", rawL, Opts{Org: orgA})
	if err != nil {
		t.Fatalf("agent.list: %v", err)
	}
	if agents := listRes.([]sqlc.Agent); len(agents) != 1 || agents[0].Name != "agent-a" {
		t.Fatalf("cross-org update mutated org A agent: %+v", agents)
	}
}

// TestAgentSkillScopedToOrg — skill attach/detach/list must be org-scoped so a
// caller in another org cannot read or mutate another org's agent skills.
func TestAgentSkillScopedToOrg(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerAgentFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgA, provA := seedOrgProvider(t, d, "org-a")
	orgB, _ := seedOrgProvider(t, d, "org-b")

	// Seed two skills directly (skills table is part of migration 0019; the
	// skill hub CRUD arrives in WU-304).
	seedSkill(t, d, "sk-1", orgA)
	seedSkill(t, d, "sk-2", orgA)

	createA := map[string]any{"org_id": orgA, "name": "agent-a", "provider_id": provA, "model": "gpt-4o"}
	rawA, _ := json.Marshal(createA)
	outA, err := d.Dispatch(ctx, userActor(), "agent.create", rawA, Opts{Org: orgA})
	if err != nil {
		t.Fatalf("create agent-a: %v", err)
	}
	agentAID := extractID(t, mustJSON(t, outA))

	// Attach a skill within org A
	attach := map[string]any{"agent_id": agentAID, "skill_id": "sk-1", "org_id": orgA}
	rawAt, _ := json.Marshal(attach)
	if _, err := d.Dispatch(ctx, userActor(), "agent.skill-attach", rawAt, Opts{Org: orgA}); err != nil {
		t.Fatalf("skill-attach: %v", err)
	}

	// Cross-org attach with a different agent id must not insert (scoped by
	// agents.org_id via the EXISTS clause).
	cross := map[string]any{"agent_id": agentAID, "skill_id": "sk-2", "org_id": orgB}
	rawC, _ := json.Marshal(cross)
	if _, err := d.Dispatch(ctx, userActor(), "agent.skill-attach", rawC, Opts{Org: orgB}); err != nil {
		t.Fatalf("cross-org skill-attach should not error, got: %v", err)
	}

	// List skills for org A — only sk-1 attached (sk-2 blocked)
	list := map[string]any{"agent_id": agentAID, "org_id": orgA}
	rawL, _ := json.Marshal(list)
	listRes, err := d.Dispatch(ctx, userActor(), "agent.list-skills", rawL, Opts{Org: orgA})
	if err != nil {
		t.Fatalf("agent.list-skills: %v", err)
	}
	got := listRes.(map[string][]string)["skills"]
	if len(got) != 1 || got[0] != "sk-1" {
		t.Fatalf("cross-org attach leaked into org A skills: got %v", got)
	}

	// Cross-org list of org A's agent must return nothing (scoped by agents.org_id)
	crossList := map[string]any{"agent_id": agentAID, "org_id": orgB}
	rawCL, _ := json.Marshal(crossList)
	crossRes, err := d.Dispatch(ctx, userActor(), "agent.list-skills", rawCL, Opts{Org: orgB})
	if err != nil {
		t.Fatalf("agent.list-skills cross-org: %v", err)
	}
	if got := crossRes.(map[string][]string)["skills"]; len(got) != 0 {
		t.Fatalf("cross-org list leaked org A skills: got %v", got)
	}
}
