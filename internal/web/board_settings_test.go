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

// TestColumnSettingsTriggerUI asserts the column settings page renders the
// trigger agent/prompt fields from the DB (WU-307).
func TestColumnSettingsTriggerUI(t *testing.T) {
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
		Context: "x", RoleID: sql.NullString{}, RetryMax: 3, BackoffSecs: 30,
		RunsPerHour: 20, TokenBudget: 50000, ApprovalPolicyJson: `{}`, Active: 1,
	}); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	proj, err := q.CreateProject(ctx, sqlc.CreateProjectParams{ID: "proj1", OrgID: org.ID, Name: "P", Key: "P1", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := q.CreateBoardColumn(ctx, sqlc.CreateBoardColumnParams{
		ID: "col1", ProjectID: proj.ID, Name: "In Progress", Color: "blue",
		Position: 1, WipLimit: 0, Status: "in_progress",
		TriggerAgentID: sql.NullString{String: "agt1", Valid: true},
		TriggerPrompt:  "Review {title} ({key})",
	}); err != nil {
		t.Fatalf("seed column: %v", err)
	}

	SetDispatcher(action.New(db))
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app/project/proj1/board/columns", nil))
	body, _ := io.ReadAll(rec.Body)
	html := string(body)

	if !strings.Contains(html, "Trigger agent") {
		t.Fatalf("column settings missing trigger agent field")
	}
	if !strings.Contains(html, "agt1") || !strings.Contains(html, "Review {title} ({key})") {
		t.Fatalf("column settings missing persisted trigger config")
	}
}
