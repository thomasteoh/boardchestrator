package perm

import (
	"context"
	"database/sql"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// TestAllowAgentIntersection — SPEC §6 AC: an agent's effective permission set
// is the intersection of its role grants and the union of allowed_actions
// across its attached skills. A granted action the agent's skills don't cover
// is denied; a skill-covered action the role doesn't grant is also denied.
func TestAllowAgentIntersection(t *testing.T) {
	d := dbtest.New(t)
	q := sqlc.New(d)
	ctx := context.Background()

	// Org.
	orgID := "org-1"
	if _, err := q.CreateOrg(ctx, sqlc.CreateOrgParams{ID: orgID, Name: "O", Slug: "o", Visibility: "private"}); err != nil {
		t.Fatalf("org: %v", err)
	}

	// Role grants task.create + task.update (not task.delete).
	roleID := "role-1"
	if _, err := q.CreateRole(ctx, sqlc.CreateRoleParams{ID: roleID, OrgID: orgID, Name: "agent-role", GrantsJson: `["task.create","task.update"]`}); err != nil {
		t.Fatalf("role: %v", err)
	}

	// Agent membership in the org, carrying the role.
	if _, err := q.CreateMembership(ctx, sqlc.CreateMembershipParams{
		ID: "m-1", OrgID: orgID, ActorID: "agent-1", ActorType: "agent",
		ResourceType: "org", ResourceID: orgID, RoleID: sql.NullString{String: roleID, Valid: true},
	}); err != nil {
		t.Fatalf("membership: %v", err)
	}

	// Provider referenced by the agent.
	if _, err := q.CreateProvider(ctx, sqlc.CreateProviderParams{
		ID: "prov-1", Kind: "openai-compatible", Name: "p", BaseUrl: "https://x.example.com/v1",
	}); err != nil {
		t.Fatalf("provider: %v", err)
	}

	// The agent row must exist (agent_skills scoping + FK require it).
	if _, err := q.CreateAgent(ctx, sqlc.CreateAgentParams{
		ID: "agent-1", OrgID: sql.NullString{String: orgID, Valid: true},
		TemplateID: sql.NullString{}, Name: "agent-1",
		ProviderID: "prov-1", Model: "gpt-4o",
	}); err != nil {
		t.Fatalf("agent: %v", err)
	}

	// Two skills: skill-a allows task.create; skill-b allows task.update.
	skillA, skillB := "sk-a", "sk-b"
	for _, s := range []struct{ id, actions string }{
		{skillA, `["task.create"]`},
		{skillB, `["task.update"]`},
	} {
		if _, err := q.CreateSkill(ctx, sqlc.CreateSkillParams{
			ID: s.id, OrgID: sql.NullString{String: orgID, Valid: true}, Name: s.id,
			AllowedActionsJson: s.actions,
		}); err != nil {
			t.Fatalf("skill %s: %v", s.id, err)
		}
	}
	// Attach both skills to the agent.
	for _, sk := range []string{skillA, skillB} {
		if err := q.CreateAgentSkill(ctx, sqlc.CreateAgentSkillParams{
			AgentID: "agent-1", SkillID: sk, ID: "agent-1",
			OrgID: sql.NullString{String: orgID, Valid: true},
		}); err != nil {
			t.Fatalf("attach %s: %v", sk, err)
		}
	}

	c := NewChecker(d)

	// task.create: role grants it AND a skill allows it → allowed.
	ok, err := c.AllowAgent(ctx, "agent-1", orgID, "task.create")
	if err != nil || !ok {
		t.Fatalf("task.create should be allowed: ok=%v err=%v", ok, err)
	}
	// task.update: role grants it AND a skill allows it → allowed.
	ok, err = c.AllowAgent(ctx, "agent-1", orgID, "task.update")
	if err != nil || !ok {
		t.Fatalf("task.update should be allowed: ok=%v err=%v", ok, err)
	}
	// task.delete: role does NOT grant it → denied.
	ok, err = c.AllowAgent(ctx, "agent-1", orgID, "task.delete")
	if err != nil || ok {
		t.Fatalf("task.delete should be denied: ok=%v err=%v", ok, err)
	}

	// Remove the update skill; task.update now denied (role grants it, no
	// skill covers it — intersection).
	if err := q.DeleteAgentSkill(ctx, sqlc.DeleteAgentSkillParams{
		AgentID: "agent-1", SkillID: skillB, ID: "agent-1",
		OrgID: sql.NullString{String: orgID, Valid: true},
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	ok, err = c.AllowAgent(ctx, "agent-1", orgID, "task.update")
	if err != nil || ok {
		t.Fatalf("task.update should be denied after detach (intersection): ok=%v err=%v", ok, err)
	}
}

// TestIntersectGrantsWildcard — a wildcard grant survives only if the skill
// union has a concrete matching action.
func TestIntersectGrantsWildcard(t *testing.T) {
	got := intersectGrants([]string{"task.*", "org.delete"}, []string{"task.create", "task.update"})
	// task.* survives (matches task.create/update); org.delete does not.
	if len(got) != 1 || got[0] != "task.*" {
		t.Fatalf("intersect got %v, want [task.*]", got)
	}
}
