package action

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// registerSkillFixtures registers the actions skills_test relies on, per the
// reset()+t.Cleanup(reset) convention (registry is not shared across tests).
func registerSkillFixtures() {
	Register(Definition{Name: "org.create", Impact: ImpactHigh, Scope: ScopePlatform, Handle: handleOrgCreate})
	Register(Definition{Name: "provider.create", Impact: ImpactHigh, Scope: ScopePlatform, Handle: handleProviderCreate})
	Register(Definition{Name: "agent.create", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "agent.create", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentCreate})
	Register(Definition{Name: "agent.skill-attach", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "agent.update", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentSkillAttach})
	Register(Definition{Name: "agent.skill-detach", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "agent.update", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentSkillDetach})
	Register(Definition{Name: "agent.list-skills", Impact: ImpactRead, Scope: ScopeOrg, Permission: "agent.list", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentListSkills})
	Register(Definition{Name: "skill.create", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "skill.create", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleSkillCreate})
	Register(Definition{Name: "skill.update", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "skill.update", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleSkillUpdate})
	Register(Definition{Name: "skill.delete", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "skill.delete", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleSkillDelete})
	Register(Definition{Name: "skill.list", Impact: ImpactRead, Scope: ScopeOrg, Permission: "skill.list", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleSkillList})
	Register(Definition{Name: "skill.latest", Impact: ImpactRead, Scope: ScopeOrg, Permission: "skill.list", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleSkillLatest})
	Register(Definition{Name: "skill.import", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "skill.create", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleSkillImport})
	Register(Definition{Name: "skill.export", Impact: ImpactRead, Scope: ScopeOrg, Permission: "skill.list", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleSkillExport})

	// Real action names used in allowed_actions lists; registered as no-op
	// fixtures so the allowed-actions subset validation (which checks the
	// registry) accepts them.
	noop := func(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) { return nil, nil }
	Register(Definition{Name: "search.query", Impact: ImpactRead, Scope: ScopeOrg, Permission: "search.query", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: noop})
	Register(Definition{Name: "task.list", Impact: ImpactRead, Scope: ScopeOrg, Permission: "task.list", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: noop})
	Register(Definition{Name: "task.create", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "task.create", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: noop})
}

func TestSkillCreateAndList(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerSkillFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, _ := seedOrgProvider(t, d, "skill-org")

	// Create an org skill.
	raw, _ := json.Marshal(map[string]any{
		"org_id":          orgID,
		"name":            "web-research",
		"description":     "Search and summarize the web.",
		"instructions":    "Use search tools, cite sources.",
		"allowed_actions": []string{"search.query"},
		"param_schema":    `{"type":"object"}`,
	})
	result, err := d.Dispatch(ctx, userActor(), "skill.create", raw, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("skill.create: %v", err)
	}
	out := mustJSON(t, result)
	skillID := extractID(t, out)

	// List returns it.
	listRaw, _ := json.Marshal(map[string]string{"org_id": orgID})
	listRes, err := d.Dispatch(ctx, userActor(), "skill.list", listRaw, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("skill.list: %v", err)
	}
	skills, ok := listRes.([]sqlc.Skill)
	if !ok {
		t.Fatalf("skill.list returned %T, want []sqlc.Skill", listRes)
	}
	if len(skills) != 1 || skills[0].Name != "web-research" {
		t.Fatalf("expected 1 web-research skill, got %+v", skills)
	}
	if skills[0].ID != skillID {
		t.Fatalf("skill id mismatch: %s != %s", skills[0].ID, skillID)
	}
}

func TestSkillCreateRejectsUnknownAllowedAction(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerSkillFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, _ := seedOrgProvider(t, d, "bad-org")

	// "no.such.action" is not in the registry — must be rejected.
	raw, _ := json.Marshal(map[string]any{
		"org_id":          orgID,
		"name":            "bad",
		"allowed_actions": []string{"no.such.action"},
	})
	if _, err := d.Dispatch(ctx, userActor(), "skill.create", raw, Opts{Org: orgID}); err == nil {
		t.Fatal("expected error for unregistered allowed action")
	}
}

func TestSkillCreateRejectsBadParamSchema(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerSkillFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, _ := seedOrgProvider(t, d, "schema-org")

	raw, _ := json.Marshal(map[string]any{
		"org_id":          orgID,
		"name":            "bad-schema",
		"allowed_actions": []string{"search.query"},
		"param_schema":    "{not json",
	})
	if _, err := d.Dispatch(ctx, userActor(), "skill.create", raw, Opts{Org: orgID}); err == nil {
		t.Fatal("expected error for invalid param_schema JSON")
	}
}

func TestSkillVersioning(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerSkillFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, _ := seedOrgProvider(t, d, "ver-org")

	// Create v1.
	raw, _ := json.Marshal(map[string]any{
		"org_id":          orgID,
		"name":            "vskill",
		"description":     "v1",
		"allowed_actions": []string{"search.query"},
	})
	res1, err := d.Dispatch(ctx, userActor(), "skill.create", raw, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("create v1: %v", err)
	}
	id1 := extractID(t, mustJSON(t, res1))

	// Update bumps to v2 (new id).
	upd, _ := json.Marshal(map[string]any{
		"id":              id1,
		"org_id":          orgID,
		"description":     "v2",
		"allowed_actions": []string{"search.query", "task.list"},
	})
	res2, err := d.Dispatch(ctx, userActor(), "skill.update", upd, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("skill.update: %v", err)
	}
	var updOut map[string]string
	if err := json.Unmarshal([]byte(mustJSON(t, res2)), &updOut); err != nil {
		t.Fatalf("decode update out: %v", err)
	}
	if updOut["version"] != "2" {
		t.Fatalf("expected version 2, got %q", updOut["version"])
	}

	// Latest resolves v2.
	latestRaw, _ := json.Marshal(map[string]string{"org_id": orgID, "name": "vskill"})
	latestRes, err := d.Dispatch(ctx, userActor(), "skill.latest", latestRaw, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("skill.latest: %v", err)
	}
	var latest map[string]string
	if err := json.Unmarshal([]byte(mustJSON(t, latestRes)), &latest); err != nil {
		t.Fatalf("decode latest: %v", err)
	}
	if latest["version"] != "2" {
		t.Fatalf("latest should be v2, got %q", latest["version"])
	}

	// Both versions listed.
	listRes, err := d.Dispatch(ctx, userActor(), "skill.list",
		json.RawMessage(`{"org_id":"`+orgID+`"}`), Opts{Org: orgID})
	if err != nil {
		t.Fatalf("skill.list: %v", err)
	}
	skills := listRes.([]sqlc.Skill)
	// list returns latest per name, so only one row (v2).
	if len(skills) != 1 || skills[0].Version != 2 {
		t.Fatalf("list should return latest (v2), got %+v", skills)
	}
}

func TestSkillImportExportRoundTrip(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerSkillFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, _ := seedOrgProvider(t, d, "io-org")

	// Create a skill, then export it.
	create, _ := json.Marshal(map[string]any{
		"org_id":          orgID,
		"name":            "io-skill",
		"description":     "import/export round trip",
		"instructions":    "Do the thing.",
		"allowed_actions": []string{"search.query", "task.list"},
		"param_schema":    `{"type":"object","properties":{"q":{"type":"string"}}}`,
	})
	resC, err := d.Dispatch(ctx, userActor(), "skill.create", create, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = extractID(t, mustJSON(t, resC))

	exportRaw, _ := json.Marshal(map[string]string{"org_id": orgID, "name": "io-skill"})
	exportRes, err := d.Dispatch(ctx, userActor(), "skill.export", exportRaw, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("skill.export: %v", err)
	}
	bundle := exportRes.(SkillBundle)

	// Import the bundle into a fresh org (round-trip).
	orgID2, _ := seedOrgProvider(t, d, "io-org-2")
	importRaw, _ := json.Marshal(map[string]any{"org_id": orgID2, "bundle": bundle})
	importRes, err := d.Dispatch(ctx, userActor(), "skill.import", importRaw, Opts{Org: orgID2})
	if err != nil {
		t.Fatalf("skill.import: %v", err)
	}
	var imported map[string]string
	if err := json.Unmarshal([]byte(mustJSON(t, importRes)), &imported); err != nil {
		t.Fatalf("decode import: %v", err)
	}
	if imported["version"] != "1" {
		t.Fatalf("imported into fresh org should be v1, got %q", imported["version"])
	}

	// Export again from org2 and compare to the original bundle (golden).
	export2, err := d.Dispatch(ctx, userActor(), "skill.export",
		json.RawMessage(`{"org_id":"`+orgID2+`","name":"io-skill"}`), Opts{Org: orgID2})
	if err != nil {
		t.Fatalf("re-export: %v", err)
	}
	bundle2 := export2.(SkillBundle)
	if !reflect.DeepEqual(bundle2, bundle) {
		t.Fatalf("import/export round-trip mismatch:\n got %+v\nwant %+v", bundle2, bundle)
	}
}

func TestSkillCrossOrgScoping(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerSkillFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgA, _ := seedOrgProvider(t, d, "org-a")
	orgB, _ := seedOrgProvider(t, d, "org-b")

	// Create a skill in org A.
	raw, _ := json.Marshal(map[string]any{
		"org_id":          orgA,
		"name":            "a-skill",
		"allowed_actions": []string{"search.query"},
	})
	resA, err := d.Dispatch(ctx, userActor(), "skill.create", raw, Opts{Org: orgA})
	if err != nil {
		t.Fatalf("create in A: %v", err)
	}
	skillAID := extractID(t, mustJSON(t, resA))

	// Update from org B must be a silent no-op (skill survives).
	upd, _ := json.Marshal(map[string]any{
		"id":              skillAID,
		"org_id":          orgB,
		"description":     "hijack",
		"allowed_actions": []string{"search.query"},
	})
	if _, err := d.Dispatch(ctx, userActor(), "skill.update", upd, Opts{Org: orgB}); err != nil {
		t.Fatalf("cross-org update should not error: %v", err)
	}

	// Delete from org B must not remove org A's skill.
	del, _ := json.Marshal(map[string]string{"id": skillAID, "org_id": orgB})
	if _, err := d.Dispatch(ctx, userActor(), "skill.delete", del, Opts{Org: orgB}); err != nil {
		t.Fatalf("cross-org delete should not error: %v", err)
	}

	// Skill A still listed in org A.
	listRes, err := d.Dispatch(ctx, userActor(), "skill.list",
		json.RawMessage(`{"org_id":"`+orgA+`"}`), Opts{Org: orgA})
	if err != nil {
		t.Fatalf("list in A: %v", err)
	}
	if skills := listRes.([]sqlc.Skill); len(skills) != 1 || skills[0].ID != skillAID {
		t.Fatalf("cross-org ops removed org A skill: %+v", skills)
	}

	// Org B list is empty.
	listB, err := d.Dispatch(ctx, userActor(), "skill.list",
		json.RawMessage(`{"org_id":"`+orgB+`"}`), Opts{Org: orgB})
	if err != nil {
		t.Fatalf("list in B: %v", err)
	}
	if skills := listB.([]sqlc.Skill); len(skills) != 0 {
		t.Fatalf("org B should have no skills: %+v", skills)
	}
}

// TestMcpEndpointSSRF — SSRF validator must reject private/loopback/link-local
// ranges and accept public hosts (SPEC §10 AC).
func TestMcpEndpointSSRF(t *testing.T) {
	cases := []struct {
		url    string
		reject bool
	}{
		{"https://example.com/tools", false},
		{"https://api.openai.com/v1", false},
		{"http://127.0.0.1:8000", true},
		{"http://localhost:8080", true},
		{"http://10.0.0.5/tools", true},
		{"http://172.16.0.1", true},
		{"http://192.168.1.10", true},
		{"http://169.254.1.1", true},
		{"ftp://example.com/x", true},
		{"https://[::1]:8443", true},
	}
	for _, c := range cases {
		err := validateMcpEndpointURL(c.url)
		if c.reject && err == nil {
			t.Errorf("url %q should be rejected", c.url)
		}
		if !c.reject && err != nil {
			t.Errorf("url %q should be accepted, got: %v", c.url, err)
		}
	}
}

// TestSkillCreateRejectsPrivateMcpEndpoint — the skill.create handler must
// reject an MCP endpoint resolving to a private range.
func TestSkillCreateRejectsPrivateMcpEndpoint(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerSkillFixtures()

	d := New(dbtest.New(t))
	ctx := context.Background()
	orgID, _ := seedOrgProvider(t, d, "ssrf-org")

	raw, _ := json.Marshal(map[string]any{
		"org_id":          orgID,
		"name":            "bad-mcp",
		"allowed_actions": []string{"search.query"},
		"mcp_endpoints":   []map[string]any{{"url": "http://localhost:8080", "name": "local"}},
	})
	if _, err := d.Dispatch(ctx, userActor(), "skill.create", raw, Opts{Org: orgID}); err == nil {
		t.Fatal("expected error for private-range MCP endpoint")
	}
}
