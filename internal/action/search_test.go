package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/search"
)

// registerSearchFixture re-registers the real search.query handler (the
// registry is wiped by reset() at the start of each test).
func registerSearchFixture() {
	Register(Definition{
		Name: "search.query", Impact: ImpactRead, Scope: ScopeOrg, Permission: "search.query",
		Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleSearchQuery,
	})
}

// seedSearchScope creates an org, a project, a membership (user -> org), and
// indexed task + comment + wiki rows for that org, all searchable via the
// term "needle". Returns the org id.
func seedSearchScope(t *testing.T, db *sql.DB, userID, orgID, projID string) string {
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
	// Org membership.
	if _, err := db.ExecContext(ctx, `INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id)
		VALUES (?, ?, ?, 'user', 'org', '')`, "m-"+userID+"-"+orgID, org.ID, userID); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	// Populate the FTS indexes (production wires the Indexer to the event bus).
	ix := search.NewIndexer(db)
	payload, _ := json.Marshal(map[string]string{
		"id": task.ID, "title": "needle task", "key": "K-1", "project_id": projID,
	})
	if err := ix.IndexEvent(ctx, "task.create", payload); err != nil {
		t.Fatalf("index task: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO comments (id, task_id, project_id, author_id, body)
		VALUES (?, ?, ?, ?, 'needle comment')`, "c-"+projID, task.ID, projID, userID); err != nil {
		t.Fatalf("seed comment: %v", err)
	}
	cp, _ := json.Marshal(map[string]string{
		"id": "c-" + projID, "body": "needle comment", "task_id": task.ID, "project_id": projID,
	})
	if err := ix.IndexEvent(ctx, "comment.create", cp); err != nil {
		t.Fatalf("index comment: %v", err)
	}
	// Wiki page for the org (wiki_fts columns: org_id, path, content).
	if _, err := db.ExecContext(ctx, `INSERT INTO wiki_fts (org_id, path, content)
		VALUES (?, ?, 'needle wiki')`, org.ID, "docs/needle.md"); err != nil {
		t.Fatalf("seed wiki: %v", err)
	}
	return org.ID
}

// TestSearchQueryOrgScoping covers WU-520 on the action path: search.query run
// as a member of org A must return only org A rows — never org B's task,
// comment, or wiki hits — and must include the org's own wiki results (the old
// caller-side FilterByVisibility pass silently dropped wiki hits).
func TestSearchQueryOrgScoping(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerSearchFixture()

	db := dbtest.New(t)
	// u1 (userActor) is a member of orgA; uOther is a member of orgB only.
	seedSearchScope(t, db, "u1", "orgA", "projA")
	seedSearchScope(t, db, "uOther", "orgB", "projB")

	d := New(db)
	ctx := context.Background()

	out, err := d.Dispatch(ctx, userActor(), "search.query",
		json.RawMessage(`{"query":"needle"}`), Opts{Org: "orgA"})
	if err != nil {
		t.Fatalf("search.query: %v", err)
	}
	raw := mustJSON(t, out)
	var res struct {
		Results []search.QueryResult `json:"results"`
	}
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(res.Results) == 0 {
		t.Fatal("uA should see their own org's task/comment/wiki results")
	}
	for _, r := range res.Results {
		got := r.OrgID
		if r.Type == "task" || r.Type == "comment" {
			got = orgOfProject(db, r.ProjectID)
		}
		if got == "orgB" {
			t.Fatalf("uA saw org B row: type=%s id=%s", r.Type, r.ID)
		}
	}
	// Wiki results must survive on the action path.
	sawWiki := false
	for _, r := range res.Results {
		if r.Type == "wiki" {
			sawWiki = true
		}
	}
	if !sawWiki {
		t.Fatal("wiki results missing from action path — FilterByVisibility used to drop them")
	}
}

// orgOfProject resolves the org id for a project (test helper for scoping
// assertions). Returns the org suffix for the "orgX" style ids used here.
func orgOfProject(db *sql.DB, projID string) string {
	ctx := context.Background()
	var orgID string
	err := db.QueryRowContext(ctx, `SELECT org_id FROM projects WHERE id = ?`, projID).Scan(&orgID)
	if err != nil {
		return ""
	}
	return orgID
}
