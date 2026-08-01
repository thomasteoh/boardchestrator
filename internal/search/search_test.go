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

	// Search should find it
	results, err := Query(ctx, d, "test", "", 10)
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

	results, err := Query(ctx, d, "searchable", "", 10)
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

	results, err := Query(ctx, d, "delete", "", 10)
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

func TestFilterByVisibility(t *testing.T) {
	d := setupDB(t)
	ctx := context.Background()

	// Create org, project, user, membership
	if _, err := d.ExecContext(ctx, `INSERT INTO orgs (id, name, slug) VALUES ('org1', 'Test Org', 'test-org')`); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := d.ExecContext(ctx, `INSERT INTO users (id, email) VALUES ('u1', 'u1@test')`); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := d.ExecContext(ctx, `INSERT INTO projects (id, org_id, name, key) VALUES ('p1', 'org1', 'Project 1', 'P1')`); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := d.ExecContext(ctx, `INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id)
		VALUES ('m1', 'org1', 'u1', 'user', 'org', '')`); err != nil {
		t.Fatalf("insert membership: %v", err)
	}

	results := []QueryResult{
		{Type: "task", ID: "t1", ProjectID: "p1"},
	}

	filtered, err := FilterByVisibility(ctx, d, results, "u1")
	if err != nil {
		t.Fatalf("FilterByVisibility: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatal("user should see their project's results")
	}

	filtered2, err := FilterByVisibility(ctx, d, results, "u2")
	if err != nil {
		t.Fatalf("FilterByVisibility (no access): %v", err)
	}
	if len(filtered2) != 0 {
		t.Fatal("non-member should see no results")
	}
}

func TestEmptyQuery(t *testing.T) {
	d := setupDB(t)
	ctx := context.Background()

	results, err := Query(ctx, d, "", "", 10)
	if err != nil {
		t.Fatalf("Query empty: %v", err)
	}
	if len(results) != 0 {
		t.Fatal("empty query should return no results")
	}
}

func TestEmptyUserFilter(t *testing.T) {
	ctx := context.Background()
	d := setupDB(t)

	results := []QueryResult{{Type: "task", ID: "t1", ProjectID: "p1"}}
	filtered, err := FilterByVisibility(ctx, d, results, "")
	if err != nil {
		t.Fatalf("FilterByVisibility empty user: %v", err)
	}
	if len(filtered) != 0 {
		t.Fatal("empty user should see nothing")
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

	results, err := Query(ctx, d, "test", "", 50)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(results) > 50 {
		t.Fatalf("got %d results, want at most 50", len(results))
	}
}
