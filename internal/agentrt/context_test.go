package agentrt

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// seedContextFixture builds the org/team/project/agent/skills/task rows the
// assembly test asserts on, returning their ids.
func seedContextFixture(t *testing.T, db *sql.DB, q *sqlc.Queries) (orgID, projectID, agentID, skillA, skillB, taskID string) {
	t.Helper()
	ctx := context.Background()

	// Author/uploader user for comment + attachment FKs.
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ('u1', 'u1@acme.test', 'U1')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	org, err := q.CreateOrg(ctx, sqlc.CreateOrgParams{
		ID: "org1", Name: "Acme", Slug: "acme",
		Context: "Acme ships widgets.", Visibility: "private",
	})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	orgID = org.ID

	team, err := q.CreateTeam(ctx, sqlc.CreateTeamParams{
		ID: "team1", OrgID: orgID, Name: "Platform", Slug: "platform",
		Context: "Platform team owns core services.", Visibility: "private",
	})
	if err != nil {
		t.Fatalf("seed team: %v", err)
	}
	_ = team

	proj, err := q.CreateProject(ctx, sqlc.CreateProjectParams{
		ID: "proj1", OrgID: orgID, TeamID: sql.NullString{String: team.ID, Valid: true},
		Name: "Board", Key: "BRD",
		Context: "The boardchestrator project.", Visibility: "private",
	})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	projectID = proj.ID

	// Provider + role for the agent.
	_, err = q.CreateProvider(ctx, sqlc.CreateProviderParams{
		ID: "prov1", Kind: "openai-compatible", Name: "Test", BaseUrl: "https://test/v1", KeyEnc: nil, ModelsJson: `["gpt-4o"]`,
	})
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	_, err = q.CreateRole(ctx, sqlc.CreateRoleParams{
		ID: "role1", OrgID: orgID, Name: "Editor", IsSystem: 0, GrantsJson: `["task.*","comment.*","agent.list"]`,
	})
	if err != nil {
		t.Fatalf("seed role: %v", err)
	}

	agent, err := q.CreateAgent(ctx, sqlc.CreateAgentParams{
		ID: "agt1", OrgID: sql.NullString{String: orgID, Valid: true},
		Name: "robo", ProviderID: "prov1", Model: "gpt-4o",
		Context:  "You are Acme's assistant.",
		RoleID:   sql.NullString{String: "role1", Valid: true},
		RetryMax: 3, BackoffSecs: 30, RunsPerHour: 20, TokenBudget: 50000,
		ApprovalPolicyJson: `{"low":"auto","read":"auto","high":"require"}`,
		Active:             1,
	})
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	agentID = agent.ID

	// Two skills with instructions + allowed actions.
	seedSkillRaw(t, db, "sk1", orgID, `triage`, `Triage incoming tasks.`, `["task.list","task.update","task.comment"]`)
	seedSkillRaw(t, db, "sk2", orgID, `labels`, `Apply labels to tasks.`, `["task.label"]`)
	skillA, skillB = "sk1", "sk2"
	if err := q.CreateAgentSkill(ctx, sqlc.CreateAgentSkillParams{AgentID: agentID, SkillID: "sk1", ID: agentID, OrgID: sql.NullString{String: orgID, Valid: true}}); err != nil {
		t.Fatalf("attach skill a: %v", err)
	}
	if err := q.CreateAgentSkill(ctx, sqlc.CreateAgentSkillParams{AgentID: agentID, SkillID: "sk2", ID: agentID, OrgID: sql.NullString{String: orgID, Valid: true}}); err != nil {
		t.Fatalf("attach skill b: %v", err)
	}

	// Task with labels, a relation, a comment, and an attachment.
	task, err := q.CreateTask(ctx, sqlc.CreateTaskParams{
		ID: "task1", ProjectID: projectID, Title: "Fix the pipeline",
		Description: "The nightly build is red.", Key: "BRD-1", KeyNum: 1,
		Points: 3, Priority: 2, Status: "todo", DueAt: "2026-09-01T00:00:00.000Z",
		SortOrder: 1,
	})
	if err != nil {
		t.Fatalf("seed task: %v", err)
	}
	taskID = task.ID

	label, err := q.CreateLabel(ctx, sqlc.CreateLabelParams{ID: "lab1", OrgID: orgID, Name: "urgent", Color: "red", Description: ""})
	if err != nil {
		t.Fatalf("seed label: %v", err)
	}
	if err := q.AddTaskLabel(ctx, sqlc.AddTaskLabelParams{TaskID: taskID, ProjectID: projectID, LabelID: label.ID}); err != nil {
		t.Fatalf("add label: %v", err)
	}
	// Parent task for the relation FK.
	if _, err := q.CreateTask(ctx, sqlc.CreateTaskParams{
		ID: "task0", ProjectID: projectID, Title: "Parent epic",
		Description: "", Key: "BRD-0", KeyNum: 0, Points: 0, Priority: 0,
		Status: "todo", DueAt: "", SortOrder: 0,
	}); err != nil {
		t.Fatalf("seed parent task: %v", err)
	}
	if _, err := q.CreateTaskRelation(ctx, sqlc.CreateTaskRelationParams{ID: "rel1", TaskID: taskID, RelatedTaskID: "task0", RelationType: "parent", ProjectID: projectID}); err != nil {
		t.Fatalf("seed relation: %v", err)
	}
	if _, err := q.CreateComment(ctx, sqlc.CreateCommentParams{ID: "cmt1", TaskID: taskID, ProjectID: projectID, AuthorID: "u1", Body: "Investigating the red build."}); err != nil {
		t.Fatalf("seed comment: %v", err)
	}
	if _, err := q.CreateAttachment(ctx, sqlc.CreateAttachmentParams{ID: "att1", OrgID: orgID, TaskID: taskID, UploaderID: "u1", Filename: "build.log", Mime: "text/plain", Size: 1024, StorageKey: "org1/task1/att1"}); err != nil {
		t.Fatalf("seed attachment: %v", err)
	}

	return orgID, projectID, agentID, skillA, skillB, taskID
}

// seedSkillRaw inserts a skills row directly (the skills hub CRUD arrives in
// WU-304; the agentrt tests need real rows for agent_skills FK + instructions).
func seedSkillRaw(t *testing.T, db *sql.DB, id, orgID, name, instructions, allowed string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO skills (id, org_id, name, version, description, instructions, allowed_actions_json)
		VALUES (?, ?, ?, 1, ?, ?, ?)`,
		id, sql.NullString{String: orgID, Valid: orgID != ""}, name, "", instructions, allowed)
	if err != nil {
		t.Fatalf("seed skill %s: %v", id, err)
	}
}

// TestContextAssemblyGolden asserts the labelled-cascade ordering and labels
// exactly (SPEC §10): org → team → project → agent → skills → task → trigger.
func TestContextAssemblyGolden(t *testing.T) {
	db := dbtest.New(t)
	q := sqlc.New(db)
	ctx := context.Background()

	_, projectID, agentID, _, _, taskID := seedContextFixture(t, db, q)

	agent, err := q.FindAgentByID(ctx, agentID)
	if err != nil {
		t.Fatalf("find agent: %v", err)
	}
	out, err := assembleContext(ctx, q, agent, "org1", taskID, projectID, "Please triage BRD-1")
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}

	// Order of labelled blocks must be fixed.
	blocks := []string{"org-context", "team-context", "project-context", "agent-context", "skill-triage", "skill-labels", "task", "trigger"}
	last := -1
	prev := ""
	for _, want := range blocks {
		idx := strings.Index(out[last+1:], "["+want+"]")
		if idx < 0 {
			t.Fatalf("missing block %q in context:\n%s", want, out)
		}
		if idx <= last {
			t.Fatalf("block %q out of order (want after %q)", want, prev)
		}
		last = idx
		prev = want
	}

	// Spot-check content and labels.
	for _, want := range []string{"Acme ships widgets.", "Platform team owns core services.", "The boardchestrator project.", "You are Acme's assistant.", "Triage incoming tasks.", "Apply labels to tasks.", "task: Fix the pipeline (BRD-1)", "labels: urgent", "relations: task0 parent", "comment: Investigating the red build.", "attachments: build.log", "Please triage BRD-1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("context missing %q:\n%s", want, out)
		}
	}

	// Each block must be closed.
	if strings.Count(out, "[/trigger]") != 1 {
		t.Fatalf("trigger block not closed once:\n%s", out)
	}
}
