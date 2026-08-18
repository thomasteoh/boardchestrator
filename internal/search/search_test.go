package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// setupDB creates a fresh in-memory SQLite DB with migrations up to 0013.
func setupDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:?_journal=WAL&_txlock=immediate")
	if err != nil {
		t.Fatalf("open :memory:: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	ctx := context.Background()

	// Run migrations 0001–0013 in order.
	for _, path := range []string{
		"../../migrations/0001_identity.up.sql",
		"../../migrations/0002_action_infra.up.sql",
		"../../migrations/0003_jobs.up.sql",
		"../../migrations/0004_orgs.up.sql",
		"../../migrations/0005_roles.up.sql",
		"../../migrations/0006_invites.up.sql",
		"../../migrations/0007_tasks.up.sql",
		"../../migrations/0008_board_columns.up.sql",
		"../../migrations/0009_saved_filters.up.sql",
		"../../migrations/0010_sprints.up.sql",
		"../../migrations/0011_sprint_tasks.up.sql",
		"../../migrations/0012_attachments.up.sql",
		"../../migrations/0013_search.up.sql",
		"../../migrations/0031_wiki_fts.up.sql",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read migration %s: %v", path, err)
		}
		if _, err := d.ExecContext(ctx, string(raw)); err != nil {
			t.Fatalf("exec migration %s: %v", path, err)
		}
	}
	return d
}

func TestIndexEvent(t *testing.T) {
	d := setupDB(t)
	ix := NewIndexer(d)
	ctx := context.Background()

	seedScope(t, d, "u1", "p1")

	// Insert a task directly
	_, err := d.ExecContext(ctx, `INSERT INTO tasks (id, project_id, title, description, key, status, priority, points)
		VALUES ('t1', 'p1', 'Test task', 'a description', 'TASK-1', 'open', 2, 3)`)
	if err != nil {
		t.Fatalf("insert task: %v", err)
	}

	// Index via event
	payload, _ := json.Marshal(map[string]string{
		"id": "t1", "title": "Test task", "description": "a description",
		"key": "TASK-1", "project_id": "p1",
	})
	if err := ix.IndexEvent(ctx, "task.create", payload); err != nil {
		t.Fatalf("IndexEvent: %v", err)
	}

	// Search should find it (user u1 is a member of the org owning p1)
	results, err := Query(ctx, d, "test", "u1", 10)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected search result, got none")
	}
	if results[0].ID != "t1" {
		t.Errorf("result id = %q, want t1", results[0].ID)
	}
	if results[0].Type != "task" {
		t.Errorf("result type = %q, want task", results[0].Type)
	}
}

func TestIndexCommentEvent(t *testing.T) {
	d := setupDB(t)
	ix := NewIndexer(d)
	ctx := context.Background()

	seedScope(t, d, "u1", "p1")

	// Need a task first (FK)
	_, err := d.ExecContext(ctx, `INSERT INTO tasks (id, project_id, title, description, key, status, priority, points)
		VALUES ('t2', 'p1', 'Test task 2', '', 'TASK-2', 'open', 2, 3)`)
	if err != nil {
		t.Fatalf("insert task: %v", err)
	}
	_, err = d.ExecContext(ctx, `INSERT INTO comments (id, task_id, project_id, author_id, body)
		VALUES ('c1', 't2', 'p1', 'u1', 'searchable comment body')`)
	if err != nil {
		t.Fatalf("insert comment: %v", err)
	}

	payload, _ := json.Marshal(map[string]string{
		"id": "c1", "body": "searchable comment body",
		"task_id": "t2", "project_id": "p1",
	})
	if err := ix.IndexEvent(ctx, "comment.create", payload); err != nil {
		t.Fatalf("IndexEvent comment: %v", err)
	}

	results, err := Query(ctx, d, "searchable", "u1", 10)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected comment result, got none")
	}
	if results[0].Type != "comment" {
		t.Errorf("result type = %q, want comment", results[0].Type)
	}
}

func TestDeleteFromIndex(t *testing.T) {
	d := setupDB(t)
	ix := NewIndexer(d)
	ctx := context.Background()

	seedScope(t, d, "u1", "p1")

	// Insert a task, then index it, then delete via event.
	_, err := d.ExecContext(ctx, `INSERT INTO tasks (id, project_id, title, description, key, status, priority, points)
		VALUES ('t3', 'p1', 'Delete me', '', 'TASK-3', 'open', 2, 3)`)
	if err != nil {
		t.Fatalf("insert task: %v", err)
	}

	payload1, _ := json.Marshal(map[string]string{
		"id": "t3", "title": "Delete me", "description": "",
		"key": "TASK-3", "project_id": "p1",
	})
	if err := ix.IndexEvent(ctx, "task.create", payload1); err != nil {
		t.Fatalf("IndexEvent create: %v", err)
	}
	payload2, _ := json.Marshal(map[string]string{"id": "t3"})
	if err := ix.IndexEvent(ctx, "task.archive", payload2); err != nil {
		t.Fatalf("IndexEvent archive: %v", err)
	}

	results, err := Query(ctx, d, "delete", "u1", 10)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, r := range results {
		if r.ID == "t3" {
			t.Fatal("deleted task still appears in results")
		}
	}
}

func TestBuildFTSQuery(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello", "hello*"},
		{"hello world", "hello* world*"},
		{`"quoted" term`, "quoted* term*"},
		{"", ""},
		{"  spaced  ", "spaced*"},
	}
	for _, c := range cases {
		got := buildFTSQuery(c.in)
		if got != c.want {
			t.Errorf("buildFTSQuery(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEmptyQuery(t *testing.T) {
	d := setupDB(t)
	ctx := context.Background()

	results, err := Query(ctx, d, "", "u1", 10)
	if err != nil {
		t.Fatalf("Query empty: %v", err)
	}
	if len(results) != 0 {
		t.Fatal("empty query should return no results")
	}

	// Empty userID (unauthenticated) returns nothing too (WU-520).
	results, err = Query(ctx, d, "test", "", 10)
	if err != nil {
		t.Fatalf("Query empty user: %v", err)
	}
	if len(results) != 0 {
		t.Fatal("unauthenticated search should return no results")
	}
}

func TestIndexNonExistent(t *testing.T) {
	d := setupDB(t)
	ix := NewIndexer(d)
	ctx := context.Background()

	payload, _ := json.Marshal(map[string]string{"id": "nonexistent", "title": "ghost"})
	err := ix.IndexEvent(ctx, "task.create", payload)
	if err != nil {
		t.Fatalf("IndexEvent non-existent: %v", err)
	}
	// Should not error — silently skip
}

func TestSearchLimit(t *testing.T) {
	d := setupDB(t)
	ix := NewIndexer(d)
	ctx := context.Background()

	seedScope(t, d, "u1", "p1")

	// Insert 60 tasks
	for i := 0; i < 60; i++ {
		id := strings.Repeat("a", 10) + string(rune('0'+i%10))
		_, _ = d.ExecContext(ctx, `INSERT INTO tasks (id, project_id, title, description, key, status, priority, points)
			VALUES (?, 'p1', 'test', '', ?, 'open', 2, 3)`, id, "K-"+string(rune('0'+i%10)))
		payload, _ := json.Marshal(map[string]string{
			"id": id, "title": "test", "key": "K", "project_id": "p1",
		})
		_ = ix.IndexEvent(ctx, "task.create", payload)
	}

	results, err := Query(ctx, d, "test", "u1", 50)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) > 50 {
		t.Fatalf("got %d results, want at most 50", len(results))
	}
}

// seedScope creates an org, a project, and an org membership for userID so the
// user can see the project's search results.
func seedScope(t *testing.T, d *sql.DB, userID, projectID string) {
	t.Helper()
	ctx := context.Background()
	orgID := "org-" + projectID
	if _, err := d.ExecContext(ctx, `INSERT INTO orgs (id, name, slug) VALUES (?, 'Org', ?)`, orgID, "slug-"+projectID); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := d.ExecContext(ctx, `INSERT INTO users (id, email) VALUES (?, ?)`, userID, userID+"@t"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := d.ExecContext(ctx, `INSERT INTO projects (id, org_id, name, key) VALUES (?, ?, 'P', 'P')`, projectID, orgID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := d.ExecContext(ctx, `INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id)
		VALUES (?, ?, ?, 'user', 'org', '')`, "m-"+userID+"-"+projectID, orgID, userID); err != nil {
		t.Fatalf("insert membership: %v", err)
	}
}

// TestQueryOrgScoping seeds two orgs and asserts a search in org A returns
// zero rows from org B across tasks, comments, and wiki (WU-520).
func TestQueryOrgScoping(t *testing.T) {
	d := setupDB(t)
	ix := NewIndexer(d)
	ctx := context.Background()

	// Org A: project pA, member uA. Org B: project pB, member uB.
	seedScope(t, d, "uA", "pA")
	seedScope(t, d, "uB", "pB")

	// Tasks + comments + wiki pages in both orgs.
	for _, p := range []string{"pA", "pB"} {
		_, err := d.ExecContext(ctx, `INSERT INTO tasks (id, project_id, title, description, key, status, priority, points)
			VALUES (?, ?, 'secret', '', ?, 'open', 2, 3)`, "t-"+p, p, "K-"+p)
		if err != nil {
			t.Fatalf("insert task %s: %v", p, err)
		}
		payload, _ := json.Marshal(map[string]string{
			"id": "t-" + p, "title": "secret", "key": "K", "project_id": p,
		})
		if err := ix.IndexEvent(ctx, "task.create", payload); err != nil {
			t.Fatalf("index task %s: %v", p, err)
		}
		_, err = d.ExecContext(ctx, `INSERT INTO comments (id, task_id, project_id, author_id, body)
			VALUES (?, ?, ?, 'u', 'secret comment')`, "c-"+p, "t-"+p, p)
		if err != nil {
			t.Fatalf("insert comment %s: %v", p, err)
		}
		cp, _ := json.Marshal(map[string]string{
			"id": "c-" + p, "body": "secret comment", "task_id": "t-" + p, "project_id": p,
		})
		if err := ix.IndexEvent(ctx, "comment.create", cp); err != nil {
			t.Fatalf("index comment %s: %v", p, err)
		}
		// Wiki page for each org (wiki_fts columns: org_id, path, content).
		_, err = d.ExecContext(ctx, `INSERT INTO wiki_fts (org_id, path, content)
			VALUES (?, ?, 'secret wiki')`, "org-"+p, "docs/secret.md")
		if err != nil {
			t.Fatalf("insert wiki %s: %v", p, err)
		}
	}

	// uA searching sees only org A rows (task, comment, wiki), never org B.
	results, err := Query(ctx, d, "secret", "uA", 50)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, r := range results {
		got := r.OrgID
		if r.Type == "task" || r.Type == "comment" {
			got = "org-" + r.ProjectID
		}
		if got == "org-pB" {
			t.Fatalf("uA saw org B row: type=%s id=%s", r.Type, r.ID)
		}
	}
	if len(results) == 0 {
		t.Fatal("uA should see their own org's rows")
	}

	// uB searching sees only org B rows, never org A.
	resultsB, err := Query(ctx, d, "secret", "uB", 50)
	if err != nil {
		t.Fatalf("Query uB: %v", err)
	}
	for _, r := range resultsB {
		got := r.OrgID
		if r.Type == "task" || r.Type == "comment" {
			got = "org-" + r.ProjectID
		}
		if got == "org-pA" {
			t.Fatalf("uB saw org A row: type=%s id=%s", r.Type, r.ID)
		}
	}
	if len(resultsB) == 0 {
		t.Fatal("uB should see their own org's rows")
	}
}
