package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/search"
)

// seedWebSearchScope creates an org, a project, a membership (user -> org), and
// an indexed task + wiki page for that org, all searchable via "needle".
func seedWebSearchScope(t *testing.T, db *sql.DB, userID, orgID, projID string) {
	t.Helper()
	ctx := context.Background()
	q := sqlc.New(db)
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES (?, ?, 'U')`, userID, userID+"@acme.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	org, err := q.CreateOrg(ctx, sqlc.CreateOrgParams{ID: orgID, Name: "Org " + orgID, Slug: "slug-" + orgID, Context: "", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	proj, err := q.CreateProject(ctx, sqlc.CreateProjectParams{ID: projID, OrgID: org.ID, Name: "P", Key: "K", Visibility: "private"})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	task, err := q.CreateTask(ctx, sqlc.CreateTaskParams{
		ID: "task-" + projID, ProjectID: proj.ID, Title: "needle task", Key: "K-1", KeyNum: 1,
		Points: 0, Priority: 0, Status: "todo", DueAt: "", SortOrder: 0,
	})
	if err != nil {
		t.Fatalf("seed task: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id)
		VALUES (?, ?, ?, 'user', 'org', '')`, "m-"+userID+"-"+orgID, org.ID, userID); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	ix := search.NewIndexer(db)
	payload, _ := json.Marshal(map[string]string{
		"id": task.ID, "title": "needle task", "key": "K-1", "project_id": projID,
	})
	if err := ix.IndexEvent(ctx, "task.create", payload); err != nil {
		t.Fatalf("index task: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO wiki_fts (org_id, path, content)
		VALUES (?, ?, 'needle wiki')`, org.ID, "docs/needle.md"); err != nil {
		t.Fatalf("seed wiki: %v", err)
	}
}

// TestSearchAPIAuthAndOrgScoping covers WU-520 on the /api/search route:
// unauthenticated → 401; an org-A member session → 200 returning only org A
// rows (never org B's task or wiki hits).
func TestSearchAPIAuthAndOrgScoping(t *testing.T) {
	db := dbtest.New(t)
	SetDispatcher(action.New(db))
	t.Cleanup(func() { disp = nil })

	seedWebSearchScope(t, db, "uA", "orgA", "projA")
	seedWebSearchScope(t, db, "uB", "orgB", "projB")

	sessions := auth.NewSessionStore(db)
	sc := auth.SessionConfig{Store: sessions, Secret: "01234567890123456789012345678901", Insecure: true}
	r := chi.NewRouter()
	r.Use(auth.CSP())
	r.Use(sc.Session())
	Routes(r)

	// Anonymous → 401.
	anon := httptest.NewRequest(http.MethodGet, "/api/search?q=needle", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, anon)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: status %d, want 401", rec.Code)
	}

	// uA member session → 200, only org A rows.
	rawA, _, err := sessions.Create(context.Background(), "uA", "", "")
	if err != nil {
		t.Fatalf("session uA: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/search?q=needle", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: rawA})
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("uA: status %d, want 200", rec2.Code)
	}

	var res struct {
		Results []search.QueryResult `json:"results"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(res.Results) == 0 {
		t.Fatal("uA should see their own org's rows")
	}
	for _, row := range res.Results {
		got := row.OrgID
		if row.Type == "task" {
			var orgID string
			if err := db.QueryRow(`SELECT org_id FROM projects WHERE id = ?`, row.ProjectID).Scan(&orgID); err == nil {
				got = orgID
			}
		}
		if got == "orgB" {
			t.Fatalf("uA saw org B row: type=%s id=%s", row.Type, row.ID)
		}
	}
}
