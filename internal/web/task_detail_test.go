package web

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// TestTaskDetailAgentThread asserts the task detail view renders the agent
// thread (runs + steps) for a task (WU-307).
func TestTaskDetailAgentThread(t *testing.T) {
	db := dbtest.New(t)
	ctx := t.Context()
	q := sqlc.New(db)

	org, err := q.CreateOrg(ctx, sqlc.CreateOrgParams{ID: "org1", Name: "Acme", Slug: "acme", Context: "", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := q.CreateProvider(ctx, sqlc.CreateProviderParams{ID: "prov1", Kind: "openai-compatible", Name: "Test", BaseUrl: "https://test/v1", KeyEnc: nil, ModelsJson: `["gpt-4o"]`}); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if _, err := q.CreateAgent(ctx, sqlc.CreateAgentParams{
		ID: "agt1", OrgID: sql.NullString{String: org.ID, Valid: true},
		Name: "robo", ProviderID: "prov1", Model: "gpt-4o",
		Context: "You are Acme's assistant.", RoleID: sql.NullString{},
		RetryMax: 3, BackoffSecs: 30, RunsPerHour: 20, TokenBudget: 50000,
		ApprovalPolicyJson: `{"low":"auto","read":"auto","high":"require"}`,
		Active:             1,
	}); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	proj, err := q.CreateProject(ctx, sqlc.CreateProjectParams{ID: "proj1", OrgID: org.ID, Name: "P", Key: "P1", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	task, err := q.CreateTask(ctx, sqlc.CreateTaskParams{
		ID: "task1", ProjectID: proj.ID, Title: "Fix login", Description: "@robo please", Key: "P1-1",
		KeyNum: 1, Points: 0, Priority: 0, Status: "in_progress", DueAt: "", SortOrder: 0,
	})
	if err != nil {
		t.Fatalf("seed task: %v", err)
	}
	if _, err := q.CreateRun(ctx, sqlc.CreateRunParams{
		ID: "run1", OrgID: org.ID, AgentID: "agt1", Trigger: "mention",
		TaskID:      sql.NullString{String: task.ID, Valid: true},
		InitiatedBy: sql.NullString{String: "u1", Valid: true},
		Status:      "succeeded",
	}); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	if err := q.CreateRunStep(ctx, sqlc.CreateRunStepParams{
		ID: "step1", RunID: "run1", Seq: 1, Kind: "tool",
		RequestJson:  `{"name":"task.list"}`,
		ResponseJson: `"ok"`,
		Tokens:       10,
		ID_2:         "run1", OrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed run step: %v", err)
	}

	SetDispatcher(action.New(db))
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app/org/org1/project/proj1/task/task1", nil))
	body, _ := io.ReadAll(rec.Body)
	html := string(body)

	if !strings.Contains(html, "Agent thread") {
		t.Fatalf("task detail missing agent thread panel")
	}
	if !strings.Contains(html, "succeeded") || !strings.Contains(html, "robo") {
		t.Fatalf("thread missing run status/agent name")
	}
	if !strings.Contains(html, "bc-step-tool") || !strings.Contains(html, "task.list") {
		t.Fatalf("thread missing step kind/request")
	}
}
